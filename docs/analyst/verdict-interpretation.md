# Verdict Interpretation — analyst hub

> **Status: ACTIVE.** One entry point for "I have a Verdict / a Finding — now what?" Interpreting
> a single Finding usually pulls from three docs that share the same confidence-tier vocabulary;
> this hub ties them together. The originals stay authoritative (and are referenced by path from
> README/CLAUDE.md) — read the section you need.

A Finding carries a **Confidence tier** (CONFIRMED > INFERRED > HYPOTHESIS) and rolls up into a
**Verdict word** (`SUSPICIOUS` / `INDETERMINATE` / `NO_EVIL`). To act on it, walk these three:

## 1. What the Verdict word means — [`../verdict-semantics.md`](../verdict-semantics.md)

`SUSPICIOUS` (found something — triage now) · `INDETERMINATE` (saw leads, couldn't corroborate —
review when convenient) · `NO_EVIL` (scoped-clean *within what was examined* — never "definitely
safe"). Mirrors `compute_verdict` in `scripts/find_evil_auto.py`. An `INDETERMINATE` on a
custody-only disk is an honest PASS, not a failure.

## 2. Is it a false positive? — [`../false-positives.md`](../false-positives.md)

The three architectural FP layers + four operational habits + the per-tool FP-risk table. Read
this before escalating a single-source or medium-severity hit. The canonical per-artifact "what it
proves / what it doesn't" table lives in [`artifact-semantics.md`](../artifact-semantics.md); the
≥2-artifact-class rule for execution claims is enforced by `correlate_findings`.

## 3. What do I do about it? — [`../finding-to-action.md`](../finding-to-action.md)

Per-MITRE-technique IR playbook: from a SUSPICIOUS/CONFIRMED Finding to concrete analyst next
steps (T1014, T1055, T1547, T1543, T1053, T1070, T1041/T1048).

## Also

- Per-tool output interpretation + expected-failure table: [`tool-playbooks.md`](tool-playbooks.md).
- Phase-by-phase walkthrough of how a Verdict is produced: [`../investigation-phases.md`](../investigation-phases.md).
