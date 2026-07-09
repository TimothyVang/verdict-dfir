# The Provability Standard for AI-Driven DFIR

*A vendor-neutral bar for making an AI forensic finding defensible — independently checkable, offline,
without trusting the system that produced it.*

> **Status:** draft standard, v0.1. VERDICT is the reference implementation; the standard is written to
> apply to **any** AI-DFIR system that emits the conformance artifacts below.

## The problem

An AI agent can produce a forensic finding. By default that finding is just an **assertion** — a
sentence. A reviewer, an opposing expert, or a court has no way to know whether it is faithful to the
evidence, reproducible, or anything more than a confident guess. Recall benchmarks ("did it find the
evil?") don't answer this; they reward a system that flags everything. The unanswered question is:
**can this finding be proven — re-checked by a third party who trusts nothing about the producer?**

This standard defines what a finding must carry to be *provable*. "Provable" here means **checkable,
not certainly correct** — see the honesty boundary at the end, which is the load-bearing part.

## Scope

Applies to a single **Finding** and to a **Case** (a set of Findings plus a scoped verdict). It is
vendor-neutral: a system claims conformance by producing the required artifacts, regardless of which
agent or tools it uses.

## The eight requirements

| # | Requirement | What it means |
|---|---|---|
| **R1 — Citation** | Every Finding cites the exact tool call (`tool_call_id`) and the canonical output hash (`output_sha256`). | An uncited claim is not a Finding; it is vetoed. |
| **R2 — Replay** | The cited tool call is deterministically re-runnable, and re-running reproduces `output_sha256`. | A third party can independently replay the evidence, offline. |
| **R3 — Fidelity** | The Finding's **asserted values** are present in the cited output (extractive entailment). | A citation that *exists* but does not *contain* the claimed value fails — this catches the model misreading evidence that is really there. |
| **R4 — Corroboration** | Execution / exfiltration claims require **≥2 independent artifact classes**; single-source claims are downgraded. Detector hits (Hayabusa/Sigma/YARA/malfind) are **leads** until corroborated. | One artifact is not a story. |
| **R5 — Scoped confidence** | Every Finding carries a tier — **CONFIRMED > INFERRED > HYPOTHESIS** — set by an explicit epistemic rule. Case verdicts are scoped: `SUSPICIOUS` / `INDETERMINATE` / `NO_EVIL`. | `NO_EVIL` means "no reportable finding in the artifacts examined," **never** a clean bill of health. |
| **R6 — Coverage boundary** | A coverage manifest enumerates per-artifact-class status: available / attempted / parsed / failed / unsupported / not-supplied. | The strongest claim is "the cited artifacts were examined through replayable tools," not "the system is clean." |
| **R7 — Custody** | The run seals into a hash-chained audit log → Merkle root over canonical tool outputs → a signed manifest, verifiable offline with no network and no trust in the producer. | Framed for **FRE 902(14)** self-authentication; flip one byte and verification fails and names the moved record. |
| **R8 — Read-only** | Evidence is hashed before access and never modified; the tool surface is read-only (no shell-escape). | The evidence you prove against is the evidence you received. |

## Provability levels (score any finding or system)

A finding — or a whole system — is rated at the **lowest** level it satisfies:

- **L0 — Asserted.** A claim with no citation. *Not provable.* (Most raw LLM output lives here.)
- **L1 — Cited** (R1). You know which tool produced it.
- **L2 — Reproducible** (R1–R2). A third party can re-run it and get the same output.
- **L3 — Faithful** (+R3). The claim matches the output — no misread of data that is present.
- **L4 — Defensible** (+R4–R8). Corroborated, scoped, coverage-bounded, custody-sealed, read-only.

The gap most AI-DFIR systems sit in today is **L1 vs L3**: they can cite a tool, but they don't prove
the claim is *faithful* to what the tool returned. R3 is the line.

## Conformance artifacts

A conformant Case produces, at minimum:

- `verdict.json` — Findings, each with tier (R5) and citation (R1).
- `coverage_manifest.json` — the per-class scope ledger (R6).
- `run.manifest.json` — the signed manifest (R7).
- `manifest_verify.json` — the offline verification result; **must report `overall: true`**.
- `audit.jsonl` — the hash-chained record (R7).

If `manifest_verify.json` is missing or `overall` is not `true`, the Case is **INCOMPLETE / CUSTODY
INVALID** and must not be described as signed or defensible.

## Legal framing (honest)

The custody model is built **for** FRE 902(14) self-authenticating evidence and for the
repeatability/transparency that Daubert/Frye-style scrutiny expects. This standard makes a finding
*more defensible and independently checkable*. It does **not** guarantee a court admits it —
admissibility is a judicial determination, not a property a tool can assert.

## The honesty boundary (the most important section)

**This standard certifies structured-value provability, not interpretive truth.**

R3 (Fidelity) covers the named values typed parsers emit — an EVTX event ID, an MFT `$SI`/`$FN`
timestamp, a registry value. It proves the system did not *misread a value that was there*. It does
**not** make an *interpretation* provable: "these two artifacts mean lateral movement" has no
deterministic oracle. Such a claim stays **HYPOTHESIS**, requires ≥2 artifact classes (R4), and a human
signs off.

A system is conformant when it is **honest about this line** — never when it claims to have made
judgment provable. The point of the standard is the opposite of overclaiming: *provable* means a third
party can re-check it, not that it is certainly correct.

## References (VERDICT reference implementation)

- `docs/cryptographic-attestation.md` — the custody chain and FRE 902(14) (R7).
- `docs/false-positives.md` — the leads-vs-facts model and the ≥2-artifact rule (R4–R6).
- `docs/verdict-semantics.md` — the scoped verdict words (R5).
- `agent-config/SOUL.md` — the epistemic hierarchy (R5).
- The fidelity/entailment check (R3 mechanism) — `docs/trust-benchmark.md` (fidelity pass rate, entailment re-check, misread rejection).
