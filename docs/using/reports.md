> **Status: ACTIVE.** How `scripts/render_report.py` turns a finished Case directory into the customer-facing `REPORT.html` / `REPORT.pdf`, what it consumes, and how to re-render after expert edits.

# Report generation & customization

After a Case is investigated, the engine renders an editorial "forensic case file"
report from the artifacts already sitting in the Case directory. `render_report.py`
is called automatically at the end of a run by `scripts/find_evil_auto.py`, and it is
also **self-contained** — you can re-run it standalone against any finished Case dir.

```bash
python scripts/render_report.py tmp/auto-runs/<case-id>/
```

The single positional argument is the **Case directory**. There are no other flags.

---

## 1. What it consumes

Everything the renderer reads lives inside the one Case directory you pass in. The
three files `main()` loads unconditionally (a missing one is a hard error):

| File | Role |
|---|---|
| `run.manifest.json` | Signed, hash-chained manifest (rs_merkle root plus the effective signer tier: Ed25519 by default, Sigstore when identity/transparency is configured, or explicit stub fallback). Drives the chain-of-custody figure and the offline-verification appendix. |
| `verdict.json` | The Verdict word plus every structured payload the report renders (see below). |
| `audit.jsonl` | Append-only, hash-chained audit log (`prev_hash` per line). Parsed line-by-line for the chain-of-custody figure; bad lines are skipped, not fatal. |

The **Findings** come from `verdict.json` under `findings` (the merged, judged set),
with rollups under `findings_summary` (`contradictions_surfaced`, `soul_md_kept`,
`soul_md_downgraded`). The renderer also pulls these keys out of `verdict.json` when
present, each gating an optional section or exhibit:

| `verdict.json` key | Feeds |
|---|---|
| `verdict`, `evidence_path` | Bottom-Line-Up-Front scorecard, masthead |
| `attack_story.attack_chain` | "How they got hacked" evidence-bound attack story + BLUF |
| `normalized_timeline.events` | Tier-1 timeline, entity rollup, event-sequence figure |
| `coverage_manifest` | Coverage Manifest section: available / attempted / parsed / failed / unsupported / not supplied per artifact class |
| `attack_coverage`, `attck_practitioner_coverage` | ATT&CK coverage tables + practitioner figure |
| `malware_triage.aggregate_iocs` | Indicators of Compromise (IOC) tables |
| `entity_index`, `indicators`, `evtx_summary` | Entity rollup, IOC leads, composition figure |
| `report_evidence_cards`, `tool_calls` | Evidence cards, process-view comparison figure |
| `rejected_finding_leads` | Non-evidentiary verifier-rejected leads for analyst review; these are excluded from final Findings |

Optional **sidecar files** in the Case dir are read only if present:
`coverage_manifest.json` (fallback for the Coverage Manifest section),
`psscan.json` (process-creation timeline figure), `timeline.json` / `timeline.csv`
(detailed event timeline + analyst CSV export note), and
`customer_release_gate.final.json` (final release-gate state). Each is best-effort:
absent or malformed JSON degrades gracefully instead of failing the render.

> Only the **45 product tools** (32 Rust + 13 Python) are audit-chained, so every
> Finding the report prints cites a `tool_call_id` traceable back through `audit.jsonl`.
> See `docs/reference/mcp-and-tools.md` for the tool surface.

---

## 2. The two outputs

The renderer writes both into the Case directory:

- **`REPORT.html`** — produced by pandoc (`--standalone --embed-resources`), with
  the matplotlib PNGs embedded and the bespoke HTML/CSS figures injected into their
  placeholder divs. Self-contained: one file, no external asset dependencies.
- **`REPORT.pdf`** — produced by printing `REPORT.html` through headless Chrome
  (`--headless --print-to-pdf --print-to-pdf-no-header`). Chrome renders to a sibling
  `REPORT.new.pdf` first; if the final rename fails (target locked open in a viewer),
  the rendered output survives at `REPORT.new.pdf` and the path is printed.

An intermediate `REPORT.md` is written first, then converted. The Markdown survives in
the Case dir, so you can read or diff the report source directly.

---

## 3. Figures, ATT&CK coverage, timeline & IOC tables

The report mixes two kinds of exhibit. **Matplotlib PNGs** are written to
`<case-dir>/figures/` and presented as light "mounted exhibits" pinned to the dark
case file:

| PNG | Source |
|---|---|
| `chain_of_custody.png` | `audit.jsonl` + `run.manifest.json` (hash-chained custody) |
| `findings_table.png` | merged Findings (first 20) |
| `psscan_timeline.png` | `psscan.json` process-creation events (only if present) |
| `practitioner_coverage.png` | `attck_practitioner_coverage` |
| `process_view_comparison.png` | `tool_calls` (pslist vs psscan vs psxview) |
| `attack_story_timeline.png` | `attack_story.attack_chain` beats |

The **scorecard**, **event-sequence story strip**, and **event-composition bars** are
vector HTML/CSS figures (no PNG) injected into `REPORT.html` after pandoc.

**ATT&CK coverage** renders as a Markdown table from `attack_coverage.targets` /
`attck_practitioner_coverage`, including which `attck_data_sources_seen` were observed,
backed by the practitioner figure.

The **normalized timeline** drives the Tier-1 key-events table and the entity rollup
(every account, host, address, and process, with first/last appearance and the
Finding IDs that cite it). When `timeline.csv` exists, the report notes the
analyst-friendly CSV export. The detailed event timeline shows the first 40 events.

**IOC tables** come from `malware_triage.aggregate_iocs` — grouped by type, up to 10
values each — plus any `indicators` IOC leads extracted during triage.

---

## 4. Re-rendering after expert edits

The report is a pure function of the Case directory. The expert-signoff loop (the
1% in the 99/1 doctrine) edits the structured artifacts — typically `verdict.json`
(Findings, attack story, coverage) — and the report is regenerated to match:

1. Apply the expert edit to the Case dir's `verdict.json` (or a sidecar like
   `timeline.json`).
2. Re-run the renderer against the same directory:
   ```bash
   python scripts/render_report.py tmp/auto-runs/<case-id>/
   ```
3. Figures, tables, `REPORT.md`, `REPORT.html`, and `REPORT.pdf` are all rebuilt
   from the edited artifacts. No flags, no partial-render mode — it always rebuilds
   the full set.

Because the chain-of-custody figure and the verification appendix read straight from
`run.manifest.json` and `audit.jsonl`, an edit to `verdict.json` alone does **not**
re-sign the manifest; re-finalize the manifest separately if the Verdict materially
changed (see `docs/reference/mcp-and-tools.md`).

---

## 5. Customer PDF: the replay-evidence-embedded blocker

A **customer-ready** PDF is gated, not just rendered. The `verify_finding_replay_embedded`
rule (`agent-config/expert-rules.json`, enforced in `scripts/find_evil_auto.py`) is a
**blocker**: every Finding in a customer release must embed verifier replay evidence,
and every replay must match the audited tool output. When a Finding carries a
`replay_artifact`, the report prints its drift class, match/no-match, and the
expected/actual SHA-256 prefixes; a replay appendix tabulates them across Findings.
If replay evidence is not embedded for every Finding, the customer release stays
behind expert review. Do not downgrade this blocker without an explicit policy change.

---

## 6. Styling & dependencies

`scripts/_report_style.css` drives the entire look — Midnight Ink, Paper Cream,
Archivo / JetBrains Mono type, Electric Cobalt and Soft Lilac brand accents, and
the Seafoam / Butter Yellow / Electric Cobalt semantic confidence colors
(`CONFIRMED` / `INFERRED` / `HYPOTHESIS`). pandoc is pointed at it via `--css`.
To restyle the report, edit that one file and re-render; it is kept in sync with
the `_DEFAULT_CSS` fallback baked into `render_report.py` (used only if the CSS
file is missing). The canonical visual rules are in [`../brand.md`](../brand.md).

**pandoc is required** for any HTML or PDF output. If pandoc is not found (and no
`PANDOC_BIN` override resolves), the renderer prints a warning and **skips the render**
entirely — figures may still be written, but no `REPORT.html` / `REPORT.pdf`. PDF
output additionally needs a Chrome/Chromium binary (or `CHROME_BIN`); without it you
get `REPORT.html` only. See `docs/reference/dependencies.md` for pinned versions and
the degrade behavior, and `docs/reference/environment-variables.md` for `PANDOC_BIN`
and `CHROME_BIN`.

| Need | Tool | Missing -> |
|---|---|---|
| HTML + PDF | `pandoc` (or `PANDOC_BIN`) | render skipped, warning printed |
| PDF | Chrome/Chromium (or `CHROME_BIN`) | `REPORT.html` only |
| Figures | matplotlib (Agg backend) | required dependency |
