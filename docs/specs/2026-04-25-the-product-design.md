# Spec #2 — The Product: FIND EVIL! Automated DFIR Pipeline

> **Status: SHIPPED (with A2 + A5 amendments and later tool additions).** The current Product ships 19 typed Rust MCP tools, 12 typed Python MCP tools, the M2 crypto stack (3-tier post-A5), and the M4 ACH agent layer (Pool A/B + judge + verifier + correlator + contradiction node). The pre-A2 LangGraph runtime + FastAPI service were never built (per A2). The Bitcoin/OpenTimestamps tier was removed (per A5). Live entry: `scripts/verdict <evidence>` (THE ONE COMMAND: preflight → investigate → live dashboard → signed verdict + report; calls the internal `scripts/find-evil-auto` engine). Original sections below describe design-era entry points (`openclaw run`, `find-evil serve|run|verify`) and the OTS/Bitcoin tier that are all **superseded** — see CLAUDE.md §11. The SANS-rubric self-assessment is likewise no longer pipeline-emitted; it is a standalone pre-submission grader (`scripts/self-score.py`). `CLAUDE.md` and the executable registries are authoritative for shipped behavior and counts.

**Date:** 2026-04-25
**Status (original):** Design — awaiting user approval (Gate 4) — superseded by status banner above
**Deadline:** 2026-06-15 22:45 CDT
**Parent:** `docs/specs/2026-04-23-find-evil-automation-master-design.md`
**Grounded in:** `BUILD_PLAN_v2.md` (DFIR fundamentals unchanged); memory files `project_dfir_tooling_picks`, `project_adversarial_agents_pattern`, `project_crypto_custody_stack`, `project_mcp_apps_readiness`, `project_judging_signals`

> **Amendment A5 (2026-05-01) supersedes the OpenTimestamps + Bitcoin
> tier of the M2 cryptographic chain-of-custody.** The "Bitcoin
> anchor" subsection of §7, acceptance criterion AC-05, the
> `opentimestamps-client` pin row in §16, and the `crypto/ots.py`
> file-tree entry in §4 are all removed in this revision. The
> `ots_pending` field on `RunVerdict` (§5) is left in place as a
> deferred wire-format decision per the A5 plan §6. The chain is
> now three composed primitives (audit prev_hash → rs_merkle →
> sigstore); the FRE 902(14) prong (b) is satisfied by Rekor
> transparency-log inclusion rather than Bitcoin proof-of-work.
> See `docs/cryptographic-attestation.md` for the honest trade-off
> on the legal claim.

---

## 1. Problem Statement

SANS Find Evil! judges run a SIFT VM with Windows host evidence in `.e01` format and have 5–20 minutes per submission. No prior submission has delivered a cryptographically-verifiable, end-to-end automated verdict. This product solves three compounding problems.

**Triage latency.** Converting a cold `.e01` to a structured timeline of malicious activity takes a trained analyst 20–90 minutes with SIFT tools used individually. This product reduces that to a supervised 3–8 minute automated run, or an unsupervised CI batch run without analyst presence.

**Evidence traceability.** Published DFIR agent tools (Dropzone, Prophet, competitor `findevil`) either emit findings without citations or cite tool output at the prose level only. The SANS rubric explicitly penalizes unlinked inferences. Every finding in this product carries a `tool_call_id` + SHA-256 that is visible in the UI chip, in the CLI output, and in the audit JSONL.

**Courtroom portability.** No existing DFIR agent tool produces cryptographically self-authenticating findings under FRE 902(14). This product signs every MCP tool call with `sigstore-python` (recorded in the public Rekor transparency log) and roots findings in an `rs_merkle` Merkle tree. Any party can verify the entire run offline without trusting the tool author. (Pre-A5 the chain also anchored the Merkle root to Bitcoin via `opentimestamps-client`; that tier was cut — see the A5 banner above.)

The product does NOT replace the analyst. It is framed throughout as "an orchestrator that reduces friction" (Rob Lee's non-negotiable, per `project_judging_signals.md`). Unattended mode is a CI/batch capability, not the primary interaction model.

---

## 2. Runtime Entry Points and Lifecycle

### 2.1 Entry Points

All four entry points share a single LangGraph investigation graph in `services/agent/graph.py`.

```
Entry point                          Transport        Primary use
─────────────────────────────────────────────────────────────────────
openclaw run --case X.e01            stdio/OpenClaw   SIFT users; demo
claude-code .                        Claude Code SDK  Interactive dev
find-evil serve                      FastAPI :8080    Browser demo; daily use
find-evil run --case X.e01           CLI              CI/batch mode
  [--unattended]
find-evil verify <manifest>          CLI              Crypto verifier
```

`openclaw run` and `claude-code .` both reach `services/agent/graph.py` directly. `find-evil serve` additionally starts FastAPI + Next.js dev proxy. `find-evil run` is a thin CLI wrapper that skips the web server.

### 2.2 Lifecycle Diagram

```
Judge / user
    │
    │  Drop X.e01 or invoke CLI
    ▼
┌─────────────────────────────────────────────────────────────┐
│  Entry layer (one of four paths above)                       │
│                        │                                     │
│               FastAPI POST /cases                            │
└────────────────────────┬────────────────────────────────────┘
                          │  case_id returned
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Agent runtime  services/agent/                              │
│                                                              │
│  LangGraph StateGraph (graph.py)                             │
│    supervisor ──► PlanProposed event                         │
│    [plan approval gate — skipped if --unattended]            │
│    supervisor ──► scatter to ACH pools                       │
│                                                              │
│  Pool A (persistence-biased)   Pool B (exfil-biased)         │
│    disk_analyst subagent         disk_analyst subagent       │
│    log_analyst subagent          log_analyst subagent        │
│    memory_analyst subagent       memory_analyst subagent     │
│            │                            │                    │
│            └────────────┬───────────────┘                    │
│                         │                                    │
│               ContradictionFound event                       │
│               (emitted BEFORE judge reconciles)              │
│                         │                                    │
│                    Judge node                                 │
│                    credibility-weighted merge                 │
│                         │                                    │
│                    Verifier node                              │
│                    re-executes tool calls                     │
│                         │                                    │
│                    Correlator node                            │
│                         │                                    │
│                    RunVerdict event                           │
└─────────────────────────┬───────────────────────────────────┘
                           │
        ┌──────────────────┼────────────────────┐
        │                  │                    │
        ▼                  ▼                    ▼
 SSE → Next.js SPA   verdict.json         notify-send
 (live investigation) (stdout if           + Slack webhook
                       --unattended)       (if configured)
                           │
                           ▼
                 M2 crypto manifest
                 sigstore-signed +
                 Merkle-rooted +
                 OTS-anchored
```

**State persistence:** `LangGraph SqliteSaver` checkpoints to `~/.findevil/cases/<case_id>/graph.db` after every node. SIGKILL-safe. `find-evil run --case X.e01 --resume` picks up from the last checkpoint without restarting tool calls.

---

## 3. Seven-Layer Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 7 — Presentation                                           │
│                                                                   │
│  Next.js 15 SPA  apps/web/                                        │
│    shadcn/ui + Tailwind v4 + TanStack + Observable Plot           │
│    NarrativePane (left) + EvidenceCanvas (right)                  │
│    HypothesisBoard MITRE grid + VerdictCard                       │
│    ContradictionSurface — analyst-decision UI                     │
│                                                                   │
│  M3 MCP App widgets  apps/mcp-widgets/                            │
│    timeline / ioc-heatmap / evidence-diff                         │
│    served from Rust MCP server; render in Claude Desktop,         │
│    ChatGPT, Cursor; deep-link back to Next.js SPA                 │
│                                                                   │
│  CLI unattended: verdict JSON → stdout; exit codes 0/1/2/3        │
│  notify-send toast + optional Slack webhook on RunVerdict         │
│  Offline report.html (Vite library build)                         │
└──────────────────────────────────────────────────────────────────┘
                            │  SSE AgentEvent stream
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 6 — Agent Runtime                                          │
│                                                                   │
│  services/agent/ — single Python process                          │
│    FastAPI (uvicorn) on :8080                                     │
│    LangGraph StateGraph + SqliteSaver checkpoint                  │
│    Claude Agent SDK subagents (one per specialist role)           │
│    pydantic-to-typescript → apps/web/lib/events.ts                │
│                                                                   │
│  services/mcp/ — Rust MCP server, stdio subprocess                │
│    rmcp 0.16.x framework; spawned at case open                    │
└──────────────────────────────────────────────────────────────────┘
                            │  MCP tool calls (stdio JSON-RPC)
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 5 — Agent Graph (M4 ACH)                                   │
│                                                                   │
│  graph.py        LangGraph StateGraph; SqliteSaver; entry point   │
│  supervisor.py   plan decomposition; scatter-gather dispatch      │
│  pools/persistence.py   Pool A — persistence-biased priors        │
│  pools/exfil.py         Pool B — exfil-biased priors              │
│  judge.py        credibility-weighted merge (Estornell 2025)      │
│  contradiction.py  ContradictionFound emit — runs before judge    │
│  verifier.py     re-execute tool calls; veto uncited findings     │
│  correlator.py   cross-artifact execution corroboration           │
│                                                                   │
│  Single debate round. Homogeneous model strength both pools.      │
│  Judge hard budget: 2 minutes wall clock.                         │
└──────────────────────────────────────────────────────────────────┘
                            │
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 4 — Memory                                                 │
│                                                                   │
│  L1  DuckDB per case  ~/.findevil/cases/<id>/evidence.ddb         │
│      Shared read-only across both ACH worker pools                │
│                                                                   │
│  L2  LangGraph SqliteSaver  graph.db  (resume mechanism)          │
│      M2 crypto-audit JSONL  audit.jsonl  (audit-only)             │
│      sigstore-python signs each line at flush                     │
│                                                                   │
│  L3  Hermes cross-case learned memory  services/hermes/           │
│      SQLite; loaded at supervisor init                            │
└──────────────────────────────────────────────────────────────────┘
                            │
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 3 — Typed Rust MCP Server                                  │
│                                                                   │
│  services/mcp/src/lib.rs  rmcp 0.16.x ServerHandler               │
│  11 typed tools (see §6); no execute_shell                        │
│                                                                   │
│  In-process (linkable — MIT/Apache-2.0):                          │
│    evtx 0.11.2      EVTX parse; 1600× python-evtx                 │
│    duckdb 0.10.x    L1 case DB                                    │
│    rs_merkle 1.4.0  Merkle tree construction                      │
│                                                                   │
│  Subprocess only (AGPL/GPL — never linked):                       │
│    Hayabusa 2.x     Sigma scoring; JSONL output                   │
│    Chainsaw v2.x    MFT carving; timeline; Shimcache/Amcache      │
│    Volatility3 2.x  memory analysis (BSD, subprocess)             │
│    Velociraptor 0.7.x  adaptive artifact collection (gRPC)        │
│    YARA Forge Core  weekly tarball; subprocess scan               │
└──────────────────────────────────────────────────────────────────┘
                            │
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 2 — SIFT Tool Subprocess Layer                             │
│                                                                   │
│  Unprivileged user — no root, no CAP_SYS_ADMIN                    │
│  Evidence vault mounted read-only                                 │
│  Wall-clock budget: 120s per tool call                            │
│  CPU: SCHED_IDLE + cpulimit 50%                                   │
│  CWD jail: /tmp/case-<id>-work (tmpfs, cleared on close)          │
│  Binary allowlist: no curl/wget/nc in subprocess path             │
└──────────────────────────────────────────────────────────────────┘
                            │
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 1 — Evidence Vault                                         │
│                                                                   │
│  /evidence/<case_id>/  read-only bind-mount                       │
│  Original .e01 opened via libewf; never mutated                   │
│  Working dir: /tmp/case-<id>-work/  (write-only)                  │
│  SHA-256 of image verified at case_open; stored in CaseHandle     │
└──────────────────────────────────────────────────────────────────┘
```

---

## 4. Module List with File Paths

### 4.1 Rust MCP Server (`services/mcp/`)

```
services/mcp/
├── Cargo.toml                      # rmcp 0.16.x, evtx 0.11.2, rs_merkle 1.4.0,
│                                   # duckdb 0.10.x, pyo3 (sigstore FFI bridge)
├── src/
│   ├── lib.rs                      # rmcp ServerHandler; tool registry
│   ├── main.rs                     # stdio transport entry point
│   ├── tools/
│   │   ├── mod.rs                  # Tool enum + dispatch table
│   │   ├── case_open.rs            # SHA-256 verify; libewf open; DuckDB init
│   │   ├── mft_timeline.rs         # Chainsaw v2 subprocess; MFT row parse
│   │   ├── evtx_query.rs           # evtx 0.11.2 in-process + DuckDB insert
│   │   ├── hayabusa_scan.rs        # Hayabusa 2.x subprocess; JSONL parse
│   │   ├── vol_pslist.rs           # Volatility3 subprocess
│   │   ├── vol_malfind.rs          # Volatility3 subprocess
│   │   ├── yara_scan.rs            # YARA subprocess; YARA Forge Core ruleset
│   │   ├── usnjrnl_query.rs        # Chainsaw v2 UsnJrnl extraction
│   │   ├── registry_query.rs       # Chainsaw v2 registry hive parse
│   │   ├── prefetch_parse.rs       # Chainsaw v2 prefetch analysis
│   │   └── vel_collect.rs          # Velociraptor gRPC artifact dispatch
│   ├── crypto/
│   │   ├── mod.rs                  # M2 crypto entry point
│   │   ├── signing.rs              # sigstore-python FFI bridge via pyo3
│   │   ├── merkle.rs               # rs_merkle append-only tree; per-call leaf insert
│   │   └── manifest.rs             # RunManifest struct; JCS (RFC 8785) serialisation
│   ├── widgets/
│   │   ├── mod.rs                  # M3 _meta.ui.resourceUri builder
│   │   ├── timeline.rs             # URI for timeline widget
│   │   ├── ioc_heatmap.rs          # URI for IOC heatmap widget
│   │   └── evidence_diff.rs        # URI for evidence-diff widget
│   └── db/
│       └── duckdb_case.rs          # DuckDB schema (events, findings,
│                                   # merkle_leaves, audit) + insert helpers
└── tests/
    ├── tool_smoke.rs               # Integration tests against OTRF Mordor fixtures
    └── merkle_roundtrip.rs         # Insert 100 leaves; prove leaf 42; verify
```

### 4.2 Python Agent Service (`services/agent/`)

```
services/agent/
├── pyproject.toml                  # langgraph>=1.0 (pin exact), anthropic>=0.45,
│                                   # fastapi>=0.115, uvicorn, sigstore==3.x,
│                                   # pydantic>=2.7, duckdb>=0.10,
│                                   # mitreattack-python  (opentimestamps-client
│                                   # was removed under Amendment A5)
├── config.py                       # MODEL constant (one value for both pools);
│                                   # tool binary paths; budget ceiling; flags
├── graph.py                        # LangGraph StateGraph; SqliteSaver.from_conn_string;
│                                   # edge order: supervisor → scatter → gather →
│                                   # contradiction_detect → judge → verify →
│                                   # correlate → verdict;
│                                   # openclaw + claude-code entry point
├── supervisor.py                   # Supervisor node; plan decomposition;
│                                   # PlanProposed event; plan approval gate;
│                                   # scatter-gather dispatch to both pools
├── pools/
│   ├── __init__.py
│   ├── persistence.py              # Pool A; system prompt: persistence priors
│   │                               # (Scheduled Tasks, Services, WMI, Run keys,
│   │                               # IFEO, LOLBins from MEMORY.md);
│   │                               # Claude Agent SDK subagents per specialist
│   └── exfil.py                    # Pool B; system prompt: exfil priors
│                                   # (net connections, staging dirs, certutil,
│                                   # bitsadmin, cloud sync, USB writes)
├── judge.py                        # Judge node; credibility-weighted merge
│                                   # (Estornell ICML 2025 formula — see §8.2);
│                                   # emits HypothesisUpdate; 2-min wall-clock budget
├── contradiction.py                # Contradiction detection node; runs BEFORE judge;
│                                   # emits ContradictionFound per disagreement;
│                                   # pauses for analyst or auto-resolves (--unattended)
├── verifier.py                     # Verifier node; re-executes tool_calls;
│                                   # vetos any Finding without tool_call_id;
│                                   # emits VerifierAction events
├── correlator.py                   # Cross-artifact corroboration; enforces SOUL.md
│                                   # "execution claims need >=2 artifact classes"
├── specialists/
│   ├── __init__.py
│   ├── disk_analyst.py             # Claude Agent SDK subagent;
│   │                               # tools: mft_timeline, usnjrnl_query,
│   │                               # prefetch_parse, registry_query
│   ├── memory_analyst.py           # Claude Agent SDK subagent;
│   │                               # tools: vol_pslist, vol_malfind
│   └── log_analyst.py              # Claude Agent SDK subagent;
│                                   # tools: evtx_query, hayabusa_scan, yara_scan
├── events.py                       # AgentEvent Pydantic union (see §5);
│                                   # pydantic-to-typescript codegen source
├── api.py                          # FastAPI app:
│                                   #   POST /cases
│                                   #   GET  /cases/{id}/stream  (SSE)
│                                   #   POST /cases/{id}/plan/approve
│                                   #   POST /cases/{id}/contradiction/resolve
│                                   #   GET  /cases/{id}/verdict
│                                   #   GET  /cases/{id}/manifest
├── mcp_client.py                   # Rust MCP stdio subprocess manager;
│                                   # JSON-RPC dispatch + response parse;
│                                   # tool_call_id generation (UUID4)
├── crypto/
│   ├── __init__.py
│   ├── signer.py                   # sigstore 3.x keyless sign per tool call;
│   │                               # one Fulcio cert per run; async Rekor batch
│   │                               # (ots.py was removed under Amendment A5)
│   └── audit_log.py                # M2 JSONL writer; hash-chain via prev_hash field
├── cli.py                          # find-evil CLI:
│                                   #   serve — FastAPI + Next.js + MCP subprocess
│                                   #   run   — graph run (+ --unattended)
│                                   #   verify — crypto verifier
└── tests/
    ├── test_graph_smoke.py         # LangGraph compile + fake AgentEvent sequence
    ├── test_kill_resume.py         # SIGKILL mid-run; resume; verdict matches
    ├── test_ach_pool_dispatch.py   # Supervisor dispatches to both pools
    ├── test_contradiction_emit.py  # ContradictionFound fires before judge node
    ├── test_judge_scoring.py       # Credibility formula math unit test
    ├── test_verifier_veto.py       # Verifier rejects Finding missing tool_call_id
    └── test_crypto_roundtrip.py    # sigstore sign → audit_log write → verify
```

### 4.3 Next.js Web App (`apps/web/`)

```
apps/web/
├── package.json                    # next 15.x, shadcn/ui, tailwindcss 4.x,
│                                   # @tanstack/react-table 8.x, @ai-sdk/react 4.x,
│                                   # observable-plot 0.6.x, duckdb-wasm
├── app/
│   ├── page.tsx                    # Landing: case list + "New Case" dropzone
│   ├── case/
│   │   ├── new/page.tsx            # Upload flow → Plan Mode modal
│   │   └── [id]/
│   │       ├── page.tsx            # Live investigation split-pane
│   │       ├── verdict/page.tsx    # Verdict card + expandable evidence
│   │       └── report.html         # Offline single-file (Vite library build)
│   └── api/stream/route.ts         # Next.js API route bridging to FastAPI SSE
├── components/
│   ├── narrative/
│   │   ├── NarrativePane.tsx       # LEFT pane; Dropzone-style reasoning flow
│   │   ├── PlanModePanel.tsx       # Pre-approval plan view; approve button
│   │   ├── StreamingSpanTree.tsx   # Tool calls + agent messages; Langfuse-style;
│   │   │                           # [confirmed · tool · sha256] chip per Finding
│   │   └── VerifierDiff.tsx        # Rejected findings fade-out animation;
│   │                               # reason in hover tooltip
│   ├── evidence/
│   │   ├── EvidenceCanvas.tsx      # RIGHT pane; tabbed
│   │   ├── TimelineTab.tsx         # Observable Plot; linked-brush; UTC timestamps
│   │   ├── HypothesisBoard.tsx     # MITRE ATT&CK grid; live confidence bars;
│   │   │                           # driven by HypothesisUpdate events
│   │   ├── EventTable.tsx          # TanStack Table + duckdb-wasm
│   │   └── ObservablesTab.tsx      # TheHive-style IOC/observable list
│   ├── verdict/
│   │   ├── VerdictCard.tsx         # One-page executive summary; expandable evidence
│   │   └── ContradictionSurface.tsx  # ContradictionFound renderer;
│   │                                 # "Trust A / Trust B / Flag" analyst buttons
│   └── chrome/
│       ├── ReadOnlyMcpBadge.tsx    # Green "read-only" indicator; always visible
│       ├── HashChainBadge.tsx      # Click to re-verify Merkle root in worker
│       ├── NotifyStatus.tsx        # Desktop + Slack notification status
│       └── KillResumeControl.tsx   # Kill/resume + SqliteSaver checkpoint status
├── lib/
│   ├── events.ts                   # AgentEvent TypeScript types (generated from
│   │                               # services/agent/events.py; committed to repo)
│   └── api.ts                      # FastAPI client + SSE useChat helpers
└── public/
    └── verifier.wasm               # WASM Merkle verifier (week-7 stretch)
```

### 4.4 MCP App Widgets (`apps/mcp-widgets/`)

```
apps/mcp-widgets/
├── timeline/
│   ├── index.html                  # Observable Plot timeline widget
│   ├── timeline.ts                 # Rendered inside MCP App iframe
│   └── manifest.json
├── ioc-heatmap/
│   ├── index.html                  # Canvas IOC heatmap
│   ├── heatmap.ts
│   └── manifest.json
├── evidence-diff/
│   ├── index.html                  # DOM evidence-diff viewer
│   ├── diff.ts
│   └── manifest.json
└── shared/
    ├── bridge.ts                   # ui/notifications/tool-result bridge;
    │                               # Cursor _meta-strip fallback via HTTP GET
    └── deeplink.ts                 # ui/open-link → Next.js SPA deep-link builder
```

### 4.5 Scripts and Config

```
scripts/
├── serve.sh                        # starts FastAPI + Next.js dev + Rust MCP;
│                                   # opens browser to localhost:8080
├── verify.sh                       # find-evil verify <manifest> wrapper
├── mcp-scanner-check.sh            # cisco-ai-defense/mcp-scanner pre-submission gate
└── install.sh                      # SIFT VM: apt deps, cargo build, uv sync,
                                    # pnpm install, tool path config

Cargo.toml         workspace root; members = [services/mcp]
pyproject.toml     uv workspace root; members = [services/agent]
pnpm-workspace.yaml  members = [apps/web, apps/mcp-widgets]
```

---

## 5. AgentEvent Union (Typed)

Defined in `services/agent/events.py` (Pydantic v2). TypeScript generated via `pydantic-to-typescript` to `apps/web/lib/events.ts`. Every event carries `case_id`, `event_id` (UUID4), and `ts` (UTC ISO-8601 trailing Z).

```python
# services/agent/events.py — interface sketch (types and field docs only)

class ToolCallStart(BaseModel):
    event_type: Literal["ToolCallStart"]
    tool_name: str
    tool_call_id: str           # UUID4; cited in every downstream Finding
    input_hash: str             # SHA-256 of JCS-canonicalized input JSON
    pool: Literal["A", "B", "shared"] | None

class ToolCallOutput(BaseModel):
    event_type: Literal["ToolCallOutput"]
    tool_call_id: str
    output_hash: str            # SHA-256 of raw output bytes (pre-parse)
    row_count: int | None
    sigstore_bundle: str | None # base64 Sigstore bundle; set after async sign
    merkle_leaf_index: int | None

class AgentMessage(BaseModel):
    event_type: Literal["AgentMessage"]
    role: Literal["supervisor","pool_a","pool_b","judge","verifier","correlator"]
    content: str                # plain-English reasoning; feeds NarrativePane

class Finding(BaseModel):
    event_type: Literal["Finding"]
    finding_id: str
    tool_call_id: str           # REQUIRED — verifier vetos if absent
    artifact_path: str
    artifact_offset: str | None
    confidence: Literal["CONFIRMED", "INFERRED", "HYPOTHESIS"]
    mitre_technique: str | None # e.g. "T1053.005"
    description: str
    pool_origin: Literal["A", "B", "merged"] | None

class VerifierAction(BaseModel):
    event_type: Literal["VerifierAction"]
    action: Literal["approved", "rejected", "downgraded"]
    finding_id: str
    reason: str                 # displayed in VerifierDiff fade-out tooltip

class ChainUpdate(BaseModel):
    event_type: Literal["ChainUpdate"]
    merkle_root: str            # hex SHA-256
    leaf_count: int
    ots_pending: bool           # True until Bitcoin confirmation received

class RunVerdict(BaseModel):
    event_type: Literal["RunVerdict"]
    verdict: Literal["CONFIRMED_EVIL","SUSPICIOUS","BENIGN","INCONCLUSIVE"]
    confidence_score: float     # 0.0–1.0
    finding_count: int
    manifest_path: str
    ots_receipt_path: str

class PlanProposed(BaseModel):
    event_type: Literal["PlanProposed"]
    plan_steps: list[str]       # ordered investigation steps
    estimated_tool_calls: int

class PlanApproved(BaseModel):
    event_type: Literal["PlanApproved"]
    approved_by: Literal["human", "auto"]  # auto only in --unattended mode

class HypothesisUpdate(BaseModel):
    event_type: Literal["HypothesisUpdate"]
    hypothesis: Literal["persistence", "exfiltration", "both", "neither"]
    pool: Literal["A", "B"]
    confidence_delta: float     # signed; drives HypothesisBoard bars
    supporting_finding_ids: list[str]

class ContradictionFound(BaseModel):
    event_type: Literal["ContradictionFound"]
    contradiction_id: str
    pool_a_claim: str           # Pool A assertion verbatim
    pool_b_claim: str           # Pool B assertion verbatim
    conflicting_tool_call_ids: list[str]
    resolution_required: bool   # True = analyst must act before judge runs

AgentEvent = Annotated[
    ToolCallStart | ToolCallOutput | AgentMessage | Finding |
    VerifierAction | ChainUpdate | RunVerdict |
    PlanProposed | PlanApproved | HypothesisUpdate | ContradictionFound,
    Field(discriminator="event_type")
]
```

SSE encoding: each event is a `data:` line containing `AgentEvent.model_dump_json()`, followed by a blank line. The frontend uses `@ai-sdk/react` `useChat` against `GET /cases/{id}/stream`.

---

## 6. MCP Tool Surface (Typed)

All 11 tools are registered in `services/mcp/src/tools/mod.rs`. No `execute_shell` exists. Every response carries `tool_call_id` (UUID4), `output_hash` (SHA-256), and optionally `_meta.ui.resourceUri` for the relevant M3 widget. Text summary in `content[0].text` is mandatory for all tools.

| Tool | Input | Return | Implementation |
|------|-------|--------|----------------|
| `case_open` | `{image_path}` | `CaseHandle` | SHA-256 verify; libewf open; DuckDB schema init |
| `mft_timeline` | `{case_id, start?, end?}` | `Vec<MftRow>` | Chainsaw v2 subprocess |
| `evtx_query` | `{case_id, evtx_path, eids?, xpath?}` | `Vec<EvtxRow>` | evtx 0.11.2 in-process + DuckDB |
| `hayabusa_scan` | `{case_id, profile?, min_level?}` | `Vec<HayabusaHit>` | Hayabusa 2.x subprocess; JSONL parse |
| `vol_pslist` | `{case_id, dump_path, profile?}` | `Vec<ProcessRow>` | Volatility3 subprocess |
| `vol_malfind` | `{case_id, dump_path, pid?}` | `Vec<MalfindRow>` | Volatility3 subprocess |
| `yara_scan` | `{case_id, target_path, ruleset}` | `Vec<YaraHit>` | YARA subprocess; YARA Forge Core |
| `usnjrnl_query` | `{case_id, start?, end?}` | `Vec<UsnRow>` | Chainsaw v2 subprocess |
| `registry_query` | `{case_id, hive_path, key_path}` | `Vec<RegistryRow>` | Chainsaw v2 subprocess |
| `prefetch_parse` | `{case_id, pf_path?}` | `Vec<PrefetchRow>` | Chainsaw v2 subprocess |
| `vel_collect` | `{case_id, artifact}` | `Vec<ArtifactRow>` | Velociraptor gRPC subprocess |

**Key return type fields:**

```
CaseHandle:   { id, db_path, image_hash: SHA256-hex, image_size_bytes }
MftRow:       { ts: ISO8601, src_attr, path, size, inode }
EvtxRow:      { event_id: u32, ts, channel, record_id, data: JSON }
HayabusaHit:  { ts, eid: u32, rule, level, details: JSON, sigma_id }
ProcessRow:   { pid, ppid, name, create_time, cmdline: Option<str> }
MalfindRow:   { pid, vad_start: hex, protection, hex_preview }
YaraHit:      { file, rule, offset, strings: Vec<str> }
UsnRow:       { ts, file_name, reason, mft_ref }
RegistryRow:  { key, value_name, value_type, data }
PrefetchRow:  { executable, run_count, last_run, volumes: Vec<str> }
ArtifactRow:  { artifact, key, value: JSON, ts: Option<ISO8601> }
```

M3 widget routing: `evtx_query`, `mft_timeline`, `usnjrnl_query` → timeline widget URI. `yara_scan`, `hayabusa_scan` → IOC heatmap URI. Verifier rejections → evidence-diff widget URI.

---

## 7. M2 Crypto Chain-of-Custody Layer

### 7.1 What Gets Signed, When, and With Which Library

**Per-tool-call signing — `sigstore` 3.x (keyless; Fulcio + Rekor)**

Triggered in `services/agent/crypto/signer.py` immediately after each `ToolCallOutput` event. The signed payload is the JCS-canonicalized (RFC 8785) JSON object:

```json
{
  "tool_call_id": "<uuid4>",
  "tool_name": "<name>",
  "input": { "...exact input dict..." },
  "output_hash": "<sha256-hex of raw output bytes>",
  "ts": "<UTC ISO-8601Z>",
  "case_id": "<uuid4>"
}
```

One ephemeral Fulcio certificate is obtained per run (not per tool call). Rekor entries are submitted asynchronously in batches. Per-call overhead after cert acquisition is under 50ms. The resulting Sigstore bundle (base64) is written to `audit.jsonl` and emitted in `ToolCallOutput.sigstore_bundle`.

**Finding + manifest Merkle root — `rs_merkle` 1.4.0 (Rust, `services/mcp/src/crypto/merkle.rs`)**

Each tool call output hash is appended as a leaf immediately after it is computed. The tree is strictly append-only. After the verifier node approves the final finding list, the supervisor invokes `manifest_finalize` which: appends all approved finding hashes as terminal leaves; computes the Merkle root; serializes `RunManifest` as JCS-canonicalized JSON to `~/.findevil/cases/<id>/run.manifest.json`. O(log n) inclusion proofs are stored per leaf in the manifest.

**(Removed under Amendment A5 — was: Bitcoin anchor via `opentimestamps-client` 0.7.2.)** The `crypto/ots.py` module, the `ots_stamp` and `ots_verify` MCP tool wrappers, and the `opentimestamps-client` dependency were all deleted. The `ots_pending` field on `RunVerdict` (§5) is left in place pending a follow-up wire-format decision per the A5 plan; today it is always `False` because nothing sets it to `True`.

**M2 crypto-audit JSONL — `~/.findevil/cases/<id>/audit.jsonl`**

Every tool call, Sigstore bundle, Merkle leaf index, approved finding, and the final manifest hash are appended sequentially. Each line carries `prev_hash` (SHA-256 of the preceding line) forming a hash chain. This file is the forensic audit artifact; it is not the resume mechanism. `graph.db` (SqliteSaver) owns resume.

### 7.2 Verify UX — `find-evil verify <manifest>`

Implemented as the `verify` subcommand in `services/agent/cli.py`. Target: under 60 seconds on a SIFT VM with network.

**Step 1 — Offline Merkle replay (no network; ~2s):**
Re-hashes all leaves from `run.manifest.json`; recomputes root; compares to stored root.

**Step 2 — Sigstore bundle verification (~10s, network):**
`cosign verify-blob --bundle <bundle>` against cached Rekor checkpoint. Confirms each tool call's input+output was signed at time of execution by a key with a valid Fulcio certificate.

**Step 3 — Receipt output:**
One-page PDF or ANSI terminal block citing FRE 902(14) verbatim. Green "VERIFIED" or red "TAMPERED" with per-step breakdown. (The pre-A5 design had a separate Step 3 "OTS verification" before this output step; removed under A5 along with the Bitcoin tier — see the banner at top.)

WASM web verifier (`apps/web/public/verifier.wasm`): week-7 stretch goal — judge pastes manifest JSON into a static page; WASM replays Merkle root offline. Not AC-gated for the 2026-06-15 deadline.

---

## 8. M4 ACH Agent Layer

### 8.1 State Flow

```
[INIT]
  supervisor.py loads case; opens L1 DuckDB; emits PlanProposed

[PLAN_APPROVAL]
  Interactive: human approves via POST /cases/{id}/plan/approve
  Unattended:  auto-approved immediately (0s timeout)
  supervisor.py emits PlanApproved{approved_by: "human"|"auto"}

[SCATTER]
  supervisor.py dispatches IDENTICAL investigation plan to both pools
  simultaneously via LangGraph scatter-gather (StateGraph merge)

  Pool A (persistence.py):
    Claude Agent SDK subagents for disk_analyst + log_analyst
    System prompt: "attacker goal is persistence — Scheduled Tasks
    (T1053.005), Services (T1543.003), WMI subscriptions (T1546.003),
    Run/RunOnce (T1547.001), IFEO (T1546.012), LOLBins (MEMORY.md)."

  Pool B (exfil.py):
    Claude Agent SDK subagents for disk_analyst + log_analyst
    System prompt: "attacker goal is exfiltration — outbound connections
    (T1071), staging dirs (T1074), certutil/bitsadmin (T1105), cloud
    sync clients (T1567), USB write activity (T1052.001)."

  Both pools share L1 DuckDB read-only. Tool calls labelled pool=A or B.

[GATHER + CONTRADICTION DETECTION]
  contradiction.py runs as dedicated LangGraph node BEFORE judge.py
  Detects: same tool_call_id cited by both pools with conflicting
    interpretations, or directly contradictory Finding pairs
  Emits ContradictionFound per disagreement
  resolution_required=True: graph pauses; ContradictionSurface UI waits
    for POST /cases/{id}/contradiction/resolve
  --unattended: sets resolution_required=False; passes all to judge;
    logs verbatim in audit.jsonl

[JUDGE]
  judge.py: credibility-weighted score merge (see §8.2)
  Emits HypothesisUpdate events as per-technique confidence is computed
  Hard 2-minute wall-clock budget; emits best-effort decision on expiry

[VERIFY]
  verifier.py: re-executes tool_calls behind every merged Finding
  Vetos any Finding without tool_call_id (VerifierAction{rejected})
  Rejected findings → VerifierDiff fade-out animation in NarrativePane

[CORRELATE]
  correlator.py: enforces SOUL.md cross-artifact rules
  Execution claims require Prefetch + Amcache/ShimCache corroboration
  or EDR telemetry; Amcache alone is insufficient

[VERDICT]
  supervisor.py assembles RunVerdict
  M2 manifest finalized; OTS stamp submitted async
  notify-send + Slack webhook fired
```

### 8.2 Judge Scoring Formula (Credibility-Weighted)

Formula in `services/agent/judge.py`, grounded in Estornell ICML 2025:

```
For each candidate Finding F:

  score_A = pool_A_confidence(F) × credibility_A
  score_B = pool_B_confidence(F) × credibility_B
  merged_confidence = (score_A + score_B) / (credibility_A + credibility_B)

Where:

  pool_X_confidence(F):
    1.0  if F.confidence == "CONFIRMED"
    0.6  if F.confidence == "INFERRED"
    0.3  if F.confidence == "HYPOTHESIS"

  credibility_X = prior_accuracy_X × (1 + corroboration_bonus_X)

  prior_accuracy_X:
    Fraction of Pool X findings approved by the verifier this run.
    Initialized to 0.5 for both pools.
    Updated incrementally after each verifier pass.

  corroboration_bonus_X:
    0.2  if Pool X finding is corroborated by a tool call from a
         different artifact class (disk vs. log vs. memory)
    0.0  otherwise

Threshold mapping:
  merged_confidence >= 0.80  →  CONFIRMED
  merged_confidence >= 0.50  →  INFERRED
  merged_confidence <  0.50  →  HYPOTHESIS
    (Finding carries both pool_a_claim and pool_b_claim)
```

Both pools use the same Claude model, configured once in `services/agent/config.py`. Heterogeneous model strength introduces the Estornell weak-agent poisoning failure and is prohibited.

### 8.3 ContradictionFound Emission Timing

`contradiction.py` is a dedicated LangGraph node placed in the edge order `GATHER → contradiction_detect → [optional pause] → judge`. Contradictions are surfaced to the analyst as structured `ContradictionFound` events before any reconciliation occurs. The `ContradictionSurface` component renders each event with both pool claims, the conflicting `tool_call_id` references, and "Trust A / Trust B / Flag for review" analyst buttons. In `--unattended` mode all contradictions flow to the judge with `resolution_required=False` and are logged verbatim in `audit.jsonl`. Contradiction resolution is the architectural moat: competitors surface disagreements only in post-run logs, if at all.

---

## 9. M3 Widget Contracts

### 9.1 Data Shape Each Widget Consumes

All three widgets are static HTML+JS bundles served at `GET /widgets/{name}/` from the Rust MCP server. Data arrives via the `ui/notifications/tool-result` MCP Apps message (SEP-1865), not direct SSE.

**Timeline widget — `apps/mcp-widgets/timeline/`**

Consumed by: `evtx_query`, `mft_timeline`, `usnjrnl_query` results.

`_meta.ui.dataUrl` payload:
```json
{
  "events": [
    { "ts": "ISO-8601Z", "label": "str", "source": "evtx|mft|usn",
      "severity": "info|medium|high|critical" }
  ],
  "case_id": "str"
}
```
Renders: Observable Plot timescale chart; color-coded by severity; linked-brush selection. Click fires deep-link to Next.js `GET /case/{id}?panel=timeline&event_id={event_id}`.

**IOC Heatmap — `apps/mcp-widgets/ioc-heatmap/`**

Consumed by: `yara_scan`, `hayabusa_scan` results.

`_meta.ui.dataUrl` payload:
```json
{
  "iocs": [
    { "rule": "str", "file": "str", "hit_count": 0, "mitre": "str|null" }
  ],
  "case_id": "str"
}
```
Renders: Canvas heatmap (rule × file matrix). Hover shows `tool_call_id` + SHA-256. Click deep-links to ObservablesTab.

**Evidence-diff viewer — `apps/mcp-widgets/evidence-diff/`**

Consumed by: `VerifierAction{rejected}` events routed through the MCP server.

`_meta.ui.dataUrl` payload:
```json
{
  "original_finding": { "description": "str", "confidence": "str" },
  "revised_finding":  { "description": "str", "confidence": "str" },
  "reason": "str",
  "tool_call_id": "str"
}
```
Renders: side-by-side DOM diff. Deep-links to VerifierDiff in NarrativePane.

### 9.2 Deep-Link Scheme to Next.js

`apps/mcp-widgets/shared/deeplink.ts` calls `ui/open-link` with:

```
http://localhost:8080/case/{case_id}?panel={timeline|observables|verdict}
  &event_id={event_id}&tool_call_id={tool_call_id}
```

`apps/web/app/case/[id]/page.tsx` reads `searchParams`, auto-selects the panel, and scrolls to the matching row.

**Fallback text:** every MCP tool response sets `content[0].text` to a plain-text summary (name, row count, top 3 findings). Renders in Windsurf, Zed, Cline, Continue, and all non-widget MCP clients. Widgets are progressive enhancement.

**Cursor `_meta` bug workaround:** `apps/mcp-widgets/shared/bridge.ts` detects absence of `_meta` and falls back to a `GET /widgets/{name}/data?case_id=X` HTTP endpoint serving identical data. Implemented from day one; not dependent on the bug being fixed.

---

## 10. Demo-Hook Alignment (Rob Lee 14:27 Template)

Target: first `[confirmed · tool · sha256]` finding visible within 10–15 seconds of run start. Demo is recorded with the browser open (Next.js SPA on screen), not terminal-only — explicit directive from `BUILD_PLAN_v2.md §9`.

**Beat map:**

```
T+00s  Terminal on screen (no GUI yet)
       $ find-evil run --case nist-hacking.E01
       [find-evil] Opening case: nist-hacking.E01
       [find-evil] SHA-256: ab12cafe...  case_id: 7c3f9a2e
       [find-evil] Plan: 1) Hayabusa Sigma scan  2) EVTX logon events
                         3) MFT timeline  4) Prefetch  5) Memory malfind

T+03s  case_open verified; Hayabusa subprocess pre-warmed

T+10s  First hayabusa_scan hit streams to terminal and NarrativePane:
       [confirmed · Hayabusa · EID:4624 · sha256:d84f… · hayabusa_scan-001]
       FINDING: Logon Type 3 from 192.168.1.105 at 2021-08-14T02:11:06Z

T+15s  Second confirmed IOC from evtx_query:
       [confirmed · evtx · EID:7045 · sha256:e91a… · evtx_query-002]
       FINDING: Service installed "SvcHelper" — T1543.003

T+25s  ContradictionFound — visible in terminal and ContradictionSurface:
       [contradiction-001]
         Pool A: scheduled task T1053.005 evidence in EVTX EID 4698
         Pool B: no corroborating MFT entry for task XML file
         → Analyst decision required (or auto-resolved in --unattended)

T+32s  Judge resolves; Finding downgraded CONFIRMED → INFERRED;
       VerifierDiff fade-out visible in NarrativePane

T+45s  Browser opens to localhost:8080
       HypothesisBoard: persistence 0.71 | exfiltration 0.43
       MITRE chips T1543.003, T1078, T1053.005 visible on grid

T+5:00 RunVerdict: CONFIRMED_EVIL (confidence 0.87; 14 findings)
       VerdictCard renders in browser
       notify-send toast fires on SIFT desktop
       manifest path printed to terminal
```

**Implementation requirements for this beat:**

1. Hayabusa must be the first tool dispatched after `case_open`. Supervisor plan always leads with `hayabusa_scan` on the EVTX directory.
2. Hayabusa subprocess must be pre-warmed inside `case_open` (fork before the agent graph starts reasoning) so the first hit reaches SSE within 15s of case open.
3. The `[confirmed · tool · sha256]` format is hard-coded in `StreamingSpanTree.tsx` and in the CLI output formatter in `services/agent/cli.py`. No deviation.
4. Contradiction events must emit to the CLI stderr stream, not only the browser SSE, so a terminal-only recording shows them.

---

## 11. Unattended Mode Specifics

`find-evil run --case X.e01 --unattended` runs the full investigation graph with no stdin interaction. Implemented via `human_in_the_loop=False` flag threaded through `graph.py` to all nodes.

**Behavioral differences from interactive mode:**

| Behavior | Interactive | Unattended |
|----------|-------------|------------|
| Plan approval | Human via POST or browser | Auto-approved immediately |
| Contradiction resolution | ContradictionSurface; analyst chooses | All forwarded to judge; `resolution_required=False` |
| Progress | SSE → Next.js SPA | ANSI log lines to stderr |
| Verdict output | VerdictCard in browser | Structured JSON to stdout |
| notify-send | Yes | Suppressed (no display assumed) |
| Slack webhook | If configured | If configured |

**Verdict JSON to stdout:**

```json
{
  "case_id": "7c3f9a2e",
  "verdict": "CONFIRMED_EVIL",
  "confidence_score": 0.87,
  "finding_count": 14,
  "manifest_path": "/home/sansforensics/.findevil/cases/7c3f9a2e/run.manifest.json",
  "ots_receipt_path": "/home/sansforensics/.findevil/cases/7c3f9a2e/run.manifest.ots",
  "run_duration_seconds": 412,
  "mitre_techniques": ["T1543.003", "T1078", "T1053.005"],
  "contradictions_found": 2,
  "contradictions_auto_resolved": 2
}
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Verdict reached: CONFIRMED_EVIL or SUSPICIOUS |
| `1` | Verdict reached: BENIGN or INCONCLUSIVE |
| `2` | Run failed: tool error, timeout, or graph exception |
| `3` | Crypto manifest error: signing failure or Merkle mismatch |

Exit code `0` does not mean clean evidence. Exit code `1` does not mean the run failed. CI pipelines key on `2` and `3` as build failures. No `LangGraph interrupt()` call is permitted when `human_in_the_loop=False`; any node that would interrupt must call `auto_resolve()` instead.

---

## 12. Acceptance Criteria

All 15 criteria run in the L3 golden-run job (`.github/workflows/l3-sift-goldens.yml`) against the NIST CFReDS Hacking Case (`cfreds_2015_data_leakage_pc.E01`, public domain, pulled from `cfreds.nist.gov`) on a QEMU SIFT VM snapshot.

- [ ] **AC-01 — End-to-end run:** `find-evil run --case nist-hacking.E01 --unattended` completes exit code 0 or 1 in under 15 minutes on a 4-core SIFT VM.
- [ ] **AC-02 — Correct verdict:** Run produces `verdict: CONFIRMED_EVIL`. At least 10 of the 14 canonical findings in `goldens/nist-hacking-case.findings.json` appear in the output (≥71% recall).
- [ ] **AC-03 — No uncited findings:** Every `Finding` in the output carries a `tool_call_id` that appears in `audit.jsonl`. Zero uncited findings in the run.
- [ ] **AC-04 — Crypto manifest offline verify:** `find-evil verify run.manifest.json` exits 0 (Steps 1–2, offline) in under 60 seconds.
- [ ] ~~**AC-05 — OTS receipt present:**~~ **REMOVED under Amendment A5** (Bitcoin/OTS tier deleted; no `run.manifest.ots` is produced).
- [ ] **AC-06 — Merkle inclusion proofs:** Spot-check 3 randomly selected leaves from `run.manifest.json`. `find-evil verify --check-leaf <index>` returns VALID for each.
- [ ] **AC-07 — Kill/resume:** SIGKILL the Python process mid-run. Restart with `find-evil run --case ... --resume`. Final verdict matches an uninterrupted run on the same fixture.
- [ ] **AC-08 — Contradiction surface:** The NIST Hacking Case run produces at least 1 `ContradictionFound` event, verifiable in `audit.jsonl`.
- [ ] **AC-09 — Plan Mode:** Without `--unattended`, `PlanProposed` event fires before any tool call. `POST /cases/{id}/plan/approve` unblocks the graph.
- [ ] **AC-10 — openclaw entry point:** `openclaw run --case nist-hacking.E01` produces the same `RunVerdict` as `find-evil run --case nist-hacking.E01`.
- [ ] **AC-11 — First IOC within 15s:** First `[confirmed]` finding line appears within 15 seconds of `case_open` completing on the NIST fixture.
- [ ] **AC-12 — Read-only enforcement:** Mount evidence vault as `ro`. Run full investigation. `inotifywait -r /evidence` records zero write events.
- [ ] **AC-13 — No execute_shell:** `mcp-scanner` (Cisco `cisco-ai-defense/mcp-scanner`) run against `services/mcp/` produces zero findings for `execute_shell` or equivalent arbitrary execution tools.
- [ ] **AC-14 — Widget text fallback:** Invoke `evtx_query` via a plain MCP client with no widget support. `content[0].text` contains a non-empty plain-text summary.
- [ ] **AC-15 — Unattended exit codes:** NIST fixture → exit 0. `fixtures/synthetic-benign.E01` → exit 1. Induced tool timeout → exit 2.

---

## 13. Risks and Mitigations

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| R-P1 | Prompt injection via malicious EVTX records | Medium | High | Tool outputs are parameterized DuckDB rows; never string-interpolated into prompts. Agent receives structured objects only. `HEARTBEAT.md` canary check runs per turn; altered canary aborts the session. Evidence content is delimited inside `<evidence>` tags before any LLM pass. |
| R-P2 | Hayabusa / Chainsaw subprocess crash mid-run | Medium | Medium | Every tool call is wrapped in a 120s wall-clock timeout. On failure, emit `ToolCallOutput{error: true, error_msg}`. Supervisor detects failure and dispatches an alternative (e.g., fall back from Hayabusa to `evtx_query` raw scan). SOUL.md hard rule: never substitute a guess. |
| R-P3 | ACH infinite debate | Low | High | Single-round hard cap enforced in `graph.py` — Pool A and Pool B each execute exactly once, no re-dispatch. Judge node has a 2-minute wall-clock budget and emits a decision when the budget expires regardless of confidence level. |
| R-P4 | OTS calendar servers unavailable at submission | Medium | Low | `ots stamp` is fire-and-forget; the manifest is Merkle-verifiable without OTS. Batch-submit and cache `.ots` receipts 48 hours before deadline. Per master design R26. |
| R-P5 | sigstore Rekor / Fulcio unavailable mid-run | Low | Medium | Signing is async and non-blocking. `sigstore.sign()` failure records `sigstore_bundle: null` in `audit.jsonl` and logs a warning. Run continues. Verification Step 2 shows PARTIAL for unsigned calls; Merkle root and OTS proof are unaffected. |
| R-P6 | LangGraph `SqliteSaver` API breaks between pin and submission | Low | High | Pin exact `langgraph` version in `pyproject.toml`. GHA runs weekly `uv lock --upgrade` canary; API changes caught within a week. Hold pin otherwise. |
| R-P7 | Cursor `_meta` strip bug unresolved by demo date | Medium | Low | `bridge.ts` HTTP-GET fallback implemented from day one. Demo is recorded on Claude Desktop (confirmed widget-capable), not Cursor. Plain-text summaries always present. |
| R-P8 | evtx crate produces different records than Hayabusa parse | Low | Medium | `tests/tool_smoke.rs` compares `evtx_query` row counts against `hayabusa_scan` on the same fixture. Divergence fails CI. Both run on the same OTRF Mordor EVTX fixture in L2 sandbox. |
| R-P9 | SIFT VM: Hayabusa / Chainsaw not on PATH | Medium | High | `install.sh` installs known-good binaries to `~/.local/bin/`. Subprocess wrappers in `services/mcp/src/tools/*.rs` use absolute paths from `config.toml`. L2 smoke test confirms path resolution before any PR merges. |
| R-P10 | LLM hallucination produces plausible false findings | Medium | High | Verifier re-executes every tool call behind every finding (AGENTS.md: veto power). Confidence labeling (CONFIRMED / INFERRED / HYPOTHESIS) is schema-enforced by Pydantic — no free-form assertions. Accuracy Report (self-assessed FPs and misses) is a first-class submission artifact per `project_judging_signals.md`. |

---

## 14. Out of Scope

The following are explicitly excluded from the 2026-06-15 submission:

- **Non-Windows evidence.** macOS `dmg`/`apfs`, Linux `ext4`, raw DD of non-Windows systems. The DFIR tool stack (Hayabusa, Chainsaw, Volatility Windows profiles) is Windows-first. Scope expansion deferred post-submission.
- **Live network capture.** PCAP ingestion, real-time traffic analysis, network flow correlation. Evidence is static `.e01` only.
- **Anti-forensics countermeasures beyond $FN/$SI comparison.** Timestomping detection beyond standard Autopsy/Chainsaw checks, log wiping recovery, rootkit detection beyond `vol_malfind`.
- **Multi-case simultaneous analysis.** One case per `find-evil serve` instance. Batch queuing deferred.
- **Cloud evidence.** Azure AD logs, AWS CloudTrail, O365 audit logs. Not in the SIFT baseline.
- **Mobile evidence.** iOS/Android images.
- **Reversible Verification (M5).** Cut per master design `§5` — judging risk and unvalidated sandbox-in-forensic-tool engineering.
- **PostgreSQL checkpointing in the Product.** The Product uses `SqliteSaver` exclusively. `PostgresSaver` belongs to the Build Swarm (Subsystem #1). The two are not mixed.
- **Graphical QEMU display in CI.** L3 runs headless. Demo recording uses the developer's local SIFT VM.

---

## 15. Implementation Schedule (Weeks 2–8)

Aligns to master design `§7` revised 8-week schedule.

| Week | Dates | Deliverables | Gate |
|------|-------|-------------|------|
| 2 | Apr 29–May 5 | Rust MCP scaffold + `case_open`, `mft_timeline`, `evtx_query`. M2 skeleton: sigstore-python signs tool calls. `ToolCallStart`/`ToolCallOutput` events flowing to SSE. | 3 tools pass `tool_smoke.rs`; signing roundtrip green |
| 3 | May 6–12 | Remaining 8 MCP tools. Hayabusa/Chainsaw subprocess wrappers. M2 complete: rs_merkle + OTS + `find-evil verify`. | All 11 tools pass smoke on OTRF Mordor; `find-evil verify` exits 0 |
| 4 | May 13–19 | LangGraph graph + SqliteSaver. Supervisor + Pool A + Pool B. Judge + contradiction nodes. ACH dispatch with fake findings. | test_kill_resume, test_ach_pool_dispatch, test_contradiction_emit green |
| 5 | May 20–26 | Correlator. Full ACH graph end-to-end on NIST fixture. HypothesisBoard UI with MITRE confidence deltas. | AC-01, AC-02, AC-08 pass on NIST |
| 6 | May 27–Jun 2 | Benchmark harness (DFIR-Metric). M1 leaderboard online. AC-03 through AC-10 pass. | L3 golden-run green; leaderboard URL live |
| 7 | Jun 3–9 | Lovable polish: Plan Mode UI, DFIR vocab audit, guardrails chrome, verifier animations, VerdictCard, notify-send/Slack. M3 widgets (all 3). | AC-11 through AC-15 pass; demo beat map in screen recording |
| 8 | Jun 10–15 | Demo recording (14:27 Lee template). Devpost package. DFIR-Metric accuracy report. mcp-scanner clean. | All 15 ACs green on L3; submission uploaded by Jun 14 |

---

## 16. Library Version Pins

| Library | Version | License | Where used |
|---------|---------|---------|------------|
| `rmcp` | 0.16.x | MIT | Rust MCP server framework |
| `evtx` (omerbenamram) | 0.11.2 | MIT/Apache-2.0 | Rust in-process EVTX parse |
| `rs_merkle` | 1.4.0 | MIT | Rust Merkle tree (M2) |
| `duckdb` (Rust) | 0.10.x | MIT | Rust L1 case DB |
| `langgraph` | >=1.0 (pin exact) | MIT | Python agent graph |
| `anthropic` (Claude Agent SDK) | >=0.45 | MIT | Python subagents |
| `fastapi` | >=0.115 | MIT | Python web server |
| `sigstore` | 3.x | Apache-2.0 | Python M2 signing |
| ~~`opentimestamps-client`~~ | ~~0.7.2~~ | ~~LGPL-3.0~~ | **REMOVED under Amendment A5** (Bitcoin/OTS tier deleted from the chain). |
| `pydantic` | >=2.7 | MIT | Python event schema |
| `mitreattack-python` | latest Apache-2.0 | Apache-2.0 | ATT&CK ID lookup |
| `next` | 15.x | MIT | Web app |
| `tailwindcss` | 4.x | MIT | Web app |
| `@ai-sdk/react` | 4.x | Apache-2.0 | Web SSE useChat |
| `observable-plot` | 0.6.x | ISC | Timeline chart |
| `@tanstack/react-table` | 8.x | MIT | EventTable |
| Hayabusa | 2.x (subprocess) | AGPL-3.0 | Sigma scoring |
| Chainsaw | v2.x (subprocess) | GPL-2.0 | MFT/Shimcache/timeline |
| Volatility3 | 2.x (subprocess) | AGPL-3.0 | Memory analysis |
| Velociraptor | 0.7.x (subprocess) | AGPL-3.0 | Artifact collection |
| YARA Forge Core | weekly tarball | Mixed (Core tier) | YARA rules |

**License compliance:** AGPL/GPL tools are subprocess-only; zero AGPL/GPL code is linked into the Rust binary or the Python agent. Submission repository license: MIT.

---

## 17. Source of Truth

- **This document** — Product (#2) implementation spec; authoritative for all Product architecture decisions.
- `docs/specs/2026-04-23-find-evil-automation-master-design.md` — 4-subsystem master design; supersedes this document on scope, budget, and moonshot decisions.
- `BUILD_PLAN_v2.md` — DFIR fundamentals, stack picks, differentiator ranking; authoritative where not contradicted here.
- `agent-config/SOUL.md`, `AGENTS.md`, `TOOLS.md`, `MEMORY.md`, `HEARTBEAT.md` — agent identity, epistemic hierarchy, tool surface, artifact semantics, liveness rules.
- Memory files in `C:/Users/newbi/.claude/projects/C--Users-newbi-Desktop-PUG-Projects-SANS-Hackathon/memory/` — `project_dfir_tooling_picks`, `project_adversarial_agents_pattern`, `project_crypto_custody_stack`, `project_mcp_apps_readiness`, `project_judging_signals` — research-validated decisions; apply without re-litigating.

---

*Gate 4: user approval of this spec unlocks week-2 implementation. This spec supersedes no prior document — it implements the Product (#2) slot in the master design.*
