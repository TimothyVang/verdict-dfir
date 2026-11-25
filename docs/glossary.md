# Glossary and FAQ

Plain-language definitions of the terms VERDICT uses, plus answers to common questions. Canonical
sources: [CLAUDE.md](../CLAUDE.md), [verdict-semantics.md](verdict-semantics.md),
[architecture.md](architecture.md), [agent-config/SOUL.md](../agent-config/SOUL.md).

## Core terms

| Term | Meaning |
|---|---|
| **VERDICT** | The DFIR agent in this repo. Point it at evidence; it returns a signed Verdict ("is there evil here?") plus a report. |
| **DFIR** | Digital Forensics & Incident Response — investigating compromised systems to determine what happened. |
| **MCP** | Model Context Protocol — the typed product tool interface supported agent runtimes call. VERDICT exposes 45 product tools across two MCP servers and adds no `execute_shell`. |
| **Runtime model** | Amendment A2: Claude Code is the canonical interactive/cloud runtime. The beta-native `scripts/verdict --agent` loop is authoritative for strict Phase 4 offline acceptance; the deterministic engine remains the default quality floor. There is no separate app server. |

## DFIR vocabulary (used deliberately throughout)

| Term | Means (not…) |
|---|---|
| **Case** | One unit of investigation, keyed by `case_id` (not session/run/job). |
| **Observable** | A piece of evidence under examination (not file/path/blob). |
| **Task** | A step the agent takes (not action/step). |
| **Finding** | A substantiated observation, each citing a `tool_call_id` (not result). |
| **Verdict** | The case conclusion: one of three words below (not conclusion/score). |
| **Confidence** | How strongly a Finding is supported (not score). |
| **Artifact class** | A category of forensic evidence (Prefetch, MFT, EVTX, Amcache, …). Execution claims need **≥2** corroborating artifact classes. |

## The three Verdicts

Full semantics in [verdict-semantics.md](verdict-semantics.md). None of them means "definitely safe."

| Verdict | Meaning |
|---|---|
| **SUSPICIOUS** | Found something; triage now. |
| **INDETERMINATE** | Saw leads but couldn't corroborate them; review when convenient. |
| **NO_EVIL** | Scoped-clean *within what was actually examined* — never "definitely safe." |

## Epistemic hierarchy (strict)

| Tier | Rule |
|---|---|
| **CONFIRMED** | Backed directly by tool output. |
| **INFERRED** | Derived from ≥2 confirmed facts; labeled as inferred. |
| **HYPOTHESIS** | A lead, not a fact; prefixed with the literal word "hypothesis:". |

## Agent topology and chain of custody

| Term | Meaning |
|---|---|
| **Pool A / Pool B** | Two subagent pools that investigate the same evidence with opposing priors (persistence-biased vs. exfil-biased). |
| **ACH** | Analysis of Competing Hypotheses — Heuer's intelligence method, here as live architecture: disagreements surface as `contradiction` records before a judge merges them. |
| **verifier / judge / correlator** | The verifier re-runs each cited tool; the judge merges Pool A/B findings with credibility weighting; the correlator links findings across the case (and across hosts in fleet mode). |
| **`tool_call_id`** | Opaque current-case tool execution identifier. Every Finding cites one or it is vetoed. |
| **`output_hash` / `_meta.output_sha256`** | SHA-256 digest of the tool's raw output. This is separate from the opaque `tool_call_id`. |
| **audit chain / `audit.jsonl`** | Append-only, hash-chained log (each record carries `prev_hash`) of every tool call and finding. |
| **Merkle root / `run.manifest.json`** | A Merkle tree over canonical tool outputs, recorded in the run manifest. |
| **manifest / `manifest_verify`** | The signed seal over the run; `manifest_verify` re-checks the chain + Merkle root **offline**. Post-A5 the chain is audit `prev_hash` → `rs_merkle` → manifest signature, with Ed25519 as the offline-verifiable default and Sigstore as the identity/transparency tier. |
| **SIFT VM** | The SANS SIFT Workstation VM (a gated ~9.3 GB download) that supplies the full disk-forensics toolchain. Needed only for disk-image inner-volume extraction. |
| **Live test** | The dev "done" gate: a real investigation producing a real Verdict + `manifest_verify overall:true` — not a smoke run. |
| **Phase 4 acceptance** | A beta-native `scripts/verdict --agent` run using real MCP calls, with no deterministic fallback, pre-dispatch audit rejection of unadvertised calls, an honestly scoped Verdict, and `manifest_verify overall:true`. Caseforge/OpenCode does not gate it. |

---

## FAQ

**Does `NO_EVIL` mean the system is safe?**
No. It means *scoped-clean within what was examined*. VERDICT never asserts "definitely safe."

**Why is there no `execute_shell` tool?**
The narrow, typed tool surface is the security pitch — it bounds what the agent can do on evidence
and keeps every action in the audit chain. Adding shell pass-through would forfeit that.

**Do I need the SIFT VM?**
Only for disk-image parity and for hosts without local Sleuth Kit/libewf. Memory, EVTX, PCAP, and
Velociraptor evidence run fully in local-host mode. Disk evidence is custody-only whenever
`disk_mount` / `disk_extract_artifacts` cannot produce supported parsed artifacts.

**Is a Claude credential required?**
Only for Claude-backed runs (one of three modes — see [CLAUDE.md "Required Setup"](../CLAUDE.md)).
The beta-native loop can use an on-prem `local`/`dgx` OpenAI-compatible endpoint without one.

**Is VERDICT's memory part of the evidence?**
No. In-flow Hermes recall is an audit-chain aid, not evidence by itself, and optional
operator-side memory sidecars are outside the audit chain entirely. Memory is never a Finding and
never upgrades a claim without current-case artifacts. See [CLAUDE.md "Non-Negotiable Guardrails"](../CLAUDE.md).

**Where does output go?**
`tmp/auto-runs/<case-id>/` — `verdict.json`, `audit.jsonl`, `run.manifest.json`, `manifest_verify.json`,
and the rendered report. The live dashboard streams it at `http://localhost:3000`.
