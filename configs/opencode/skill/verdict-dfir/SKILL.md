---
name: verdict-dfir
description: Use for any digital forensics & incident response (DFIR) investigation driven with the VERDICT forensic MCP tools — triaging disk/memory/EVTX/network/registry evidence, interpreting artifacts, applying Analysis of Competing Hypotheses, and sealing an evidence-bound verdict with chain of custody. Load this before running the /triage, /disk, /memory, /evtx, /network, /velociraptor, /fleet, or /verdict commands.
---

# VERDICT DFIR investigation

You are running a **read-only, evidence-bound** forensic investigation with the
VERDICT `findevil-mcp` (Rust DFIR primitives) and `findevil-agent-mcp` (Python
reasoning, crypto, custody) tool surfaces. Show me the evidence — every Finding
must cite the exact tool call that produced it.

## Core discipline

- **Evidence over assumption.** Never assert a fact you did not read from a tool
  output. Don't trust the model — reproduce the finding.
- **Read-only on evidence.** Tools hash (SHA-256) every output; the audit chain
  is your source of truth.
- **Use exact opencode MCP tool names.** Rust DFIR tools are exposed as
  `findevil-mcp_<tool>` (for example `findevil-mcp_case_open`,
  `findevil-mcp_registry_query`). Python custody/ACH tools are exposed as
  `findevil-agent-mcp_<tool>` (for example
  `findevil-agent-mcp_verify_finding`, `findevil-agent-mcp_manifest_finalize`,
  `findevil-agent-mcp_manifest_verify`). Call these as tools with structured
  arguments. Do not type MCP names into bash, do not emit JSON examples as a
  substitute for tool calls, and do not invent underscore variants such as
  `findevil_mcp_manifest_finalize`.
- **Manifest tools are Python custody tools only.** Never call
  `findevil-mcp_manifest_finalize` or `findevil-mcp_manifest_verify`; use
  `findevil-agent-mcp_manifest_finalize` and
  `findevil-agent-mcp_manifest_verify`.
- **Three verdict words only:** `SUSPICIOUS` (reportable evidence found),
  `INDETERMINATE` (coverage too limited to decide), `NO_EVIL` (no finding in the
  artifacts actually examined). Never imply more certainty than the evidence
  supports.
- **Custody.** The reason/seal phase hash-chains `audit.jsonl` → Merkle root →
  signed `run.manifest.json`, verifiable offline.

## Reference doctrine (read as needed)

- [`reference/MEMORY.md`](reference/MEMORY.md) — how to interpret each artifact
  class (Volatility, EVTX, USN journal, registry, Prefetch, MFT, PCAP).
- [`reference/GROUNDING.md`](reference/GROUNDING.md) — grounding rules: what
  counts as evidence, how to cite tool calls, anti-hallucination.
- [`reference/JUDGING.md`](reference/JUDGING.md) — Analysis of Competing
  Hypotheses scoring and verdict assignment.
- [`reference/EXPERT.md`](reference/EXPERT.md) — expert sign-off doctrine and
  stop conditions.
- [`reference/TOOLS.md`](reference/TOOLS.md) — the full product MCP tool surface.

## Workflow

1. Scope the case with the matching slash command (`/triage` for a mixed case
   directory; `/disk`, `/memory`, `/evtx`, `/network`, `/velociraptor` per
   evidence type; `/fleet` for many hosts).
2. Run the playbook's tool sequence; record each tool call and its hash.
3. Reason: apply ACH (`reference/JUDGING.md`), form competing hypotheses,
   re-verify cited tool calls.
4. Seal with the `findevil-agent-mcp_audit_verify`,
   `findevil-agent-mcp_manifest_finalize`, and
   `findevil-agent-mcp_manifest_verify` tools — produce the signed manifest and
   the scoped verdict word with its citations. Do not call nonexistent report
   QA tools or slash commands during a locked local run.

Stop and ask the operator whenever a stop condition in `reference/EXPERT.md`
fires (destructive action needed, out-of-scope, ambiguous authorization).
