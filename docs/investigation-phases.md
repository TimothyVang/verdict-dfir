# Investigation Phases

How a Find Evil! investigation is structured, what each phase produces, and where to look in the delivered artifacts.

---

## Overview

```
case_open
    │
    ├─→ Pool A (persistence-biased)  ─┐
    └─→ Pool B (exfil-biased)         ├─ run in parallel
                                       │
                               detect_contradictions
                                       │
                               analyst resolves (or auto in --unattended)
                                       │
                               verify_finding (per finding)
                                       │
                               judge_findings (credibility-weighted merge)
                                       │
                               correlate_findings (≥2 artifact-class enforcement)
                                       │
                               manifest_finalize (terminal)
```

---

## Phase 1 — Case open

**Tool:** `case_open`

**What it does:** SHA-256 hashes the evidence, records image size and path, returns a `case_id`.

**What it produces in audit.jsonl:** a `kind=case_open` record with `image_hash`, `image_size_bytes`, `case_id`, and the path.

**Analyst note:** the SHA-256 at this step is the chain-of-custody hash — the same value that should appear in your evidence receipt. If the hash doesn't match your receipt, stop and document the discrepancy before proceeding.

---

## Phase 2 — Parallel pools

**Roles:** Pool A (persistence) + Pool B (exfiltration), running simultaneously.

**What they do:** each pool runs the PLAYBOOK.md tool sequence for the evidence type (disk, memory, EVTX, etc.) with a different interpretive bias. Same MCP tools, different framing.

| Pool | Bias | Primary TTPs |
|---|---|---|
| A | The attacker is *staying* | T1547 Run keys, T1543 Services, T1546 IFEO/WMI, T1053 Scheduled Tasks, T1014 DKOM |
| B | The attacker is *taking something* | T1041/T1048 Exfiltration, T1567 Web Service, T1052 USB, T1070 indicator removal, LOLBin staging |

**What each pool produces:**
- A list of Findings, each with: `title`, `confidence` (CONFIRMED/INFERRED/HYPOTHESIS), `tool_call_id` (the tool call that produced the raw evidence), `mitre_technique`, `pool_origin` (A or B).
- `pool_origin=A` and `pool_origin=B` Findings on the same artifact with different confidence labels become contradictions.

**Prior-case memory:** before drafting each Finding, pools call `memory_recall` against the cross-case SQLite store. If a prior-case hit exists, the Finding gains a `prior_observations` field — context only, not additional evidence for the ≥2 artifact-class rule.

---

## Phase 3 — Contradiction surface

**Tool:** `detect_contradictions`

**What it does:** compares Pool A and Pool B findings that reference the same artifact or technique. Surfaces disagreements as `kind=ContradictionFound` audit records before any merging.

**Why this matters:** a single-agent architecture would resolve these disagreements internally, invisibly. This surface forces them into the audit chain where the analyst can see and override them.

**What a contradiction looks like in audit.jsonl:**
```json
{
  "kind": "ContradictionFound",
  "finding_id": "abc123",
  "pool_a_confidence": "CONFIRMED",
  "pool_b_confidence": "HYPOTHESIS",
  "pool_a_reasoning": "...",
  "pool_b_reasoning": "...",
  "auto_resolved": false
}
```

**Analyst action (attended mode):** you choose Trust A / Trust B / Flag for expert review. In `--unattended` mode, the higher-credibility pool wins automatically and the resolution is logged with `approved_by: "auto"`.

---

## Phase 4 — Verification

**Tool:** `verify_finding` (called once per Finding)

**What it does:** re-runs the `tool_call_id` the Finding cited, recomputes the output SHA-256, and checks it byte-for-byte against the original audit-log entry.

**Pass:** SHA-256 matches → `action=approved` recorded. The Finding is reproducible.

**Fail cases:**
- Finding has no `tool_call_id` → **vetoed outright**. A finding without a tool citation cannot be verified and is dropped.
- SHA-256 mismatch → tool was re-run with the same arguments and produced different output. The verifier downgrades the Finding (usually CONFIRMED → INFERRED) or rejects it and records the reason.

**What it produces in audit.jsonl:** a `kind=acp_handoff` record from the verifier to the judge, structured as `{finding_id, action, replay_record_sha256}`. This is the IBM-ACP envelope — it lets the judge trace exactly which verifier decision applies to each finding.

**Analyst note:** a vetoed finding means the agent cited a tool call that either didn't happen or produced a non-reproducible result. This is the most important quality gate in the pipeline.

---

## Phase 5 — Judging

**Tool:** `judge_findings`

**What it does:** credibility-weighted merge of Pool A and Pool B findings. Each pool's weight = `base_confidence × pool_credibility`. Pools that produced CONFIRMED corroborated findings build credibility across the investigation; pools with only HYPOTHESIS findings are downweighted.

**What it produces:** a merged finding list with per-finding explanations of which pool contributed what and how the credibility weights resolved disagreements.

**Analyst note:** if a finding you expect to see is missing, check whether it was downgraded here. The per-finding explanation will name the pool weight that caused the downgrade.

---

## Phase 6 — Correlation

**Tool:** `correlate_findings`

**What it does:** enforces the ≥2 artifact-class rule from SOUL.md. Any "X executed" or execution-implied finding must cite at least two distinct artifact classes (e.g., Prefetch + EVTX 4688, or memory + EDR telemetry). Single-source execution claims are downgraded.

**Outcome per finding:** `kept` or `downgraded`, with a reason string naming the missing artifact class.

**What to check:** look at any `downgraded` findings in the correlation output. If you have external evidence (EDR logs, a separate Velociraptor collection) that would provide the second artifact class, you can supply it and re-run to upgrade those findings.

---

## Phase 7 — Finalize

**Tool:** `manifest_finalize`

**What it produces:** `run.manifest.json` — the signed manifest covering the audit chain, Merkle root, and effective signer tier. Also writes the final `verdict.json`.

**What verdict.json contains:**

| Field | Meaning |
|---|---|
| `verdict` | `SUSPICIOUS`, `INDETERMINATE`, or `NO_EVIL` — see `docs/verdict-semantics.md` |
| `confirmed_findings[]` | Findings that survived verification and correlation at CONFIRMED level |
| `inferred_findings[]` | Findings at INFERRED level |
| `hypothesis_findings[]` | Findings kept for analyst attention but not corroborated |
| `case_completeness` | Which artifact classes were examined vs. available |
| `analysis_limitations` | Gaps in coverage (e.g., disk image provided but not mounted) |
| `attack_story` | Narrative summary of the confirmed/inferred finding chain |

---

## What `covered_no_finding` means

`covered_no_finding` in a tool result means: the tool ran successfully over the evidence scope, and found no qualifying indicators. It is **not**:
- Evidence the technique didn't occur
- A clean bill of health
- Absence of the artifact class

It means "the tools we ran didn't find it within the scope we looked." Coverage gaps are listed in `analysis_limitations`.

---

## Pause points in attended mode

The supervisor pauses and waits for analyst input at three moments:

1. **Contradiction surface** — Trust A, Trust B, or Flag for expert review
2. **Verifier veto** — re-run the cited tool yourself, or downgrade the finding manually
3. **Final manifest review** — confirm before the manifest is signed

These are resumable — the audit chain is hash-chained, so you can stop mid-investigation and restart from the last record.
