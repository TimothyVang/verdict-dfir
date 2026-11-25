---
name: verdict-dfir
description: Run local-first, evidence-bound digital forensics and incident response (DFIR) investigations with VERDICT. Enforces REA-style retained Evidence envelopes, fail-closed CaseForge privacy routing, API-boundary citation checks, >=2 artifact-class corroboration, and Skeptic verification.
metadata:
  version: "1.0.0"
---

# VERDICT — REA for DFIR

> **The LLM is not the forensic source of truth.** Every reportable finding must cite verified `evidence_id` records from the append-only session ledger. Real evidence stays local by default (`--privacy local-only`).

## Workflow (5-Phase Gated Pipeline)

1. **Doctor & Privacy Check:** Run `verdict_doctor` (or `verdict doctor --json`) only when tool availability is unknown. Verify privacy mode (`local-only` default for sensitive evidence).
2. **Catalog (`verdict_intake`):** Run `verdict_intake` with `detail: "summary"` to classify and SHA-256 hash evidence. Page large inventories via `inspect_analysis_view` using `{"kind": "retained-evidence", "evidence_id": "<parent_evidence_id>"}`.
3. **Extract & Correlate:** Run narrow, read-only forensic tools (`findevil-mcp` Rust tools, Tier-1 SIFT tools, or Tier-2 `morluto/rea` bridge for binary reversing). Never use raw shell to mutate evidence.
4. **Challenge (Skeptic / Alternative Narrative):** Before finalizing, challenge every candidate finding with `challenge_finding`, track unresolved gaps with `record_unknown` / `update_unknown`, and verify >=2 distinct artifact classes for `confirmed` findings.
5. **Verdict & Bundle:** Call `verdict_summary` and `export_evidence_bundle`. `NO_EVIL` is scoped strictly to completely examined artifacts and is never issued when open unknowns or partial coverage remain.

## Hard Rules

- **No fabricated citations:** `record_finding` rejects any `evidence_refs` not present in the session `EvidenceLedger`.
- **Amcache caveat:** Amcache proves file presence / LastModified metadata, never execution. Acknowledge this caveat explicitly or corroborate with execution artifacts.
- **Coverage honesty:** Source coverage (`complete` | `partial` | `unknown`) is distinct from page exhaustion. An empty page on partial source coverage never proves absence.
- **See** `references/evidence-workflows.md` for retained view queries, bundle import/export, and recovery error handling.
