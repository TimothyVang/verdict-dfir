# AGENTS.md — VERDICT Monorepo Operating Charter

This repository (`/home/assessor/Desktop/verdict`) is the single canonical monorepo for **VERDICT (REA for DFIR)**, consolidating `verdict-dfir-beta`, `caseforge-core`, and the unified REA-style MCP/CLI/plugin layer.

## Core Invariants (Never Violate)

1. **The LLM is not the forensic source of truth.** Every finding submitted via `record_finding` must cite verified `evidence_id` records from the append-only session `EvidenceLedger`.
2. **Real evidence stays local by default.** Fail-closed privacy mode is `local-only`; evidence class defaults to `sensitive`. Never commit real forensic images, private signing keys (`~/Documents/spark-findevil-preserve-2026-07-18`), or customer artifacts.
3. **REA Evidence discipline:**
   - Every evidence-producing tool returns a canonical `EvidenceRecord` with deterministic `evidence_id` (`ev_<sha256>`), `coverage`, `limitations`, and `analysis_profile`.
   - High-cardinality tools default to `detail: "summary"` and page via `inspect_analysis_view`.
   - Unresolved questions are tracked explicitly with `record_unknown` / `update_unknown`.
   - Source coverage (`complete` | `partial` | `unknown`) is distinct from page exhaustion.
4. **Forensic schema rules:**
   - `confirmed` findings require `>=2` distinct artifact classes across cited evidence.
   - Amcache citations require acknowledging the LastModified ≠ execution caveat.
   - `NO_EVIL` is never issued when open unknowns or incomplete coverage exist.
5. **License hygiene:** This repo is **Apache-2.0**. Never copy AGPL-3.0 code (e.g., from `DFIR-Companion`); implement clean-room patterns only.

## Build & Verify Commands

- Core TypeScript build: `npm run build:core`
- Full TypeScript build: `npm run build`
- MCP & CLI tests: `npm test`
- Rust workspace check: `cargo check --workspace`
- Host readiness: `npm run doctor`
