# Community feedback, and what we changed

When VERDICT launched we posted it to r/computerforensics, r/digitalforensics, and
r/rust and asked practitioners, directly, *"where does this break?"* They told us — in
detail, and not gently. This page preserves that criticism **verbatim** and answers it
point by point with what we actually shipped.

The threads are no longer live: the r/rust crosspost was removed by mods, and the
comment threads have since been taken down. We captured the comments on 2026-06-20 and
keep them here because the feedback was good and it changed the product. Quotes are
lightly trimmed; attribution is the commenter's Reddit handle.

Throughout, we try to be honest about what is **done**, what is **opt-in**, and what is
**partial** — overclaiming a fix would repeat exactly the mistake the feedback called
out.

> See the headline fix running: the [feature deep-dive (6:37)](https://youtu.be/jw6etogNzhY) shows the
> live agent self-correct on camera, and [`fact-fidelity.md`](fact-fidelity.md) walks the entailment
> gate rejecting a misread on purpose.

---

## What they said → what we did

### 1. "Citation-existence ≠ claim-fidelity" — the hardest one

> **ProofLegitimate9990** (r/computerforensics): "your verifier validates the existence
> of a citation, not the fidelity of the claim to the raw output beneath it, so the LLM
> can still misread a real hex dump, misinterpret a standard registry value, or
> confidently connect two benign artifacts and launder the hallucination through a valid
> tool_call_id. If you add a deterministic layer that checks whether the finding's content
> is actually **entailed** by the tool output it points to … you will have solved the hard
> part."

> **Cypher_Blue** (r/computerforensics): "under the hood it's just a super advanced
> predictive text algorithm … I'd advise caution about the way you promote this."

This was right, and it was the gap we hadn't closed. A valid `tool_call_id` only proved a
finding *pointed at* real, unchanged output — not that the model *read it correctly*.

**What we did:** a deterministic **fact-fidelity (entailment) gate**, now **on by
default**. A CONFIRMED finding must declare the specific values it claims are present
(`asserted_values`: `{path, expected, match}`); a non-LLM check re-extracts each from the
re-run tool output and rejects the finding if the value isn't actually there
(`services/agent/findevil_agent/entailment.py`, `verifier.py`). We added **anchor-class
grounding** (a count claim must be backed by ≥N entailed leaves, not one) and a
**falsifiable-expectation** field the verifier can refute. Offline `manifest_verify`
reports `entailment_ok`.
*Honest scope:* it bites for every finding that declares values, but not every emitter
declares them yet — it's a mechanism that's enforced where present and being rolled
across emitters, not a claim that hallucination is "solved."

### 2. "Two pools are one brain in two costumes"

> **ProofLegitimate9990**: "your two pools are the same model with the same training
> weights and biases. They are not independent examiners; they are one brain arguing with
> itself in two costumes. If they share a blind spot, they will reconcile around it."

Correct — model-vs-model agreement can converge on a shared hallucination.

**What we did:** put **deterministic, non-LLM checks in the consensus path** rather than
trusting Pool-A-vs-Pool-B agreement: the entailment gate above, the ≥2-artifact-class
execution rule, and an opt-in **anti-coherence "too clean" gate** that fails a CONFIRMED
finding which recorded no counter-hypothesis (`judge.py`). *Honest scope:* the
anti-coherence/counter-hypothesis gates are **opt-in** today, not default.

### 3. "Surface the artifacts; don't render the verdict"

> **ProofLegitimate9990**: "A tool that reliably surfaces suspicious artifacts and shows
> the analyst exactly where they were found is far more usable than an AI that tries to
> render the verdict itself. Improve the analyst's efficiency; don't replace their
> judgment."
> **SituationNormalAllFU**: "The LLM should be the investigator's powerful assistant, not
> the investigator."

Fair — we'd scoped too broadly.

**What we did:** leaned all the way into "surfaces for a human, decides nothing on its
own." Verdict words are strictly scoped (`docs/verdict-semantics.md`): `NO_EVIL` means
*nothing reportable in the artifacts examined* — never an environment-wide clean bill —
and every release is gated behind explicit **human expert sign-off**. The custody chain
is built so a person signs the receipt; the tool never self-certifies for release.

### 4. "It won't hold up in court"

> **Drevicar** (r/digitalforensics): "No judge will allow an AI tool to submit evidence
> without a certified human to hold accountable."
> **spicesucker**: "the whole point of forensics is your process is meant to be
> recreatable from step 1 by a third party (with the same tools) … neither of which you
> can demonstrate with a black box LLM. Saying 'I had two LLMs check it' isn't defensible."
> **Stofzik**: "most people will not want to risk their evidence being thrown out."

The deepest point — and one where we'd mis-sold our own strength. Our actual mechanism
*is* "recreatable from step 1 by a third party": a hash-chained audit log → Merkle root →
**Ed25519-signed manifest** that `manifest_verify` checks **offline**, plus `verify_finding`
that re-runs each cited tool call. The audience heard "LLM" and stopped.

**What we did:** repositioned around the receipts, not the AI — *"deterministic,
offline-reproducible custody that a human signs,"* not *"AI verdict"*
(`docs/cryptographic-attestation.md`, README). The crypto was already there; we stopped
burying it. We don't claim court-admissibility — that's a human's call — only that the
process is third-party reproducible.

### 5. "LLM-deletes-LLM raises false negatives"

> **spicesucker**: "having an LLM factcheck and delete the other LLM's findings if it
> disagrees also drastically increases the likelihood of false negatives … its job is to
> filter *for* objects you might be looking for, not filter *out* something you might be."

**What we did:** the verifier/correlator **never silently delete**. A rejected or
downgraded finding stays in the hash-chained audit as a logged `course_correction` /
demotion record, and a rejected/errored tool call is logged too — conservative and
visible, not a vanish.

### 6. "This could become a SIEM firehose"

> **Routine-Pipe8923**: "Verdict DFIR could potentially create a large number of cases,
> similar to a SIEM platform if the rules are not properly tuned … does the platform
> primarily focus on evidence collection and correlation rather than long-term storage?"

A fair operator concern. VERDICT is per-case collection + correlation + a signed verdict,
not a long-term case store; tuning case volume is real future work and we're not claiming
it's solved.

### 7. Coverage and overconfidence (our own honest read, which they sharpened)

> **ImTimothyVang** (maintainer): "the main issue is coverage and overconfidence … if the
> parser/tooling doesn't actually support an artifact then the agent can't just pretend it
> looked at it. It has to say 'indeterminate' or 'unsupported' … yara/hayabusa hits that
> look scary but are just leads."

**What we did:** an **evidence-agnostic hard rule** (detection keys on general DFIR
signatures, never per-image names) enforced by `scripts/evidence-agnostic-smoke.py`;
honest `INDETERMINATE` / `unsupported` semantics; a `coverage_manifest` recording
available/attempted/parsed/unsupported classes; Hayabusa/Sigma/YARA/malfind treated as
**leads until corroborated**; bounded extraction (default 512 MiB cap); and new parsers to
close real gaps (Outlook Express `oe_dbx_parse`, network-recon, registry triage Findings).

---

## Did it move the needle on rivals?

We re-scanned 185 related projects and deep-scanned the strongest 16. None reached
VERDICT's custody parity — Ed25519 + Merkle + **offline** `manifest_verify` with a
per-finding verifier. Rivals are genuinely ahead on cloud/identity-plane detection,
in-product accuracy harnesses, and large-scale ingest; we adopted patterns from them. The
unique axis remains third-party-reproducible custody, which is exactly what the court
thread (above) said the field is missing.

---

## Still open (because pretending otherwise is the failure mode they flagged)

- The entailment gate is enforced where findings declare values; not every emitter
  declares them yet.
- Counter-hypothesis / anti-coherence gates are opt-in, not default.
- Real-corpus recall and long-tail parser breadth are still being measured, honestly.

If you have more of this kind of feedback, that's the most useful thing you can send us.
The criticism above made the product better; we'd rather hear it than not.
