# Multi-axis forensic-image grader (Proof A)

`scripts/score-image-run.mjs` grades a sealed VERDICT run against a per-artifact
forensic-image oracle (`fixtures/dfir-image-bench/<case>/ground-truth.json`, schema
`dfir-image-oracle/v1`). It is Proof A of the forensic-image benchmark: the multi-axis grader
and oracle built and tested as **pure code, with no lab, no forensic toolchain, and no image** —
scored against a real captured offline run's actual `verdict.json` fields.

## Axes (each bound to fields the producer actually emits)

- **MITRE elevation** — expected techniques (alias-aware, so ATT&CK renumbering can't rot the
  oracle) vs the run's *structured* `findings[].mitre_technique` + `attack_coverage.observed_techniques`
  + `attack_story.attack_chain[].mitre_technique` (not a stringify of narrative, which over-counts).
- **IOC recovery** — recall of planted IOCs over **only the categories the verdict emits**
  (`accounts, file_paths, hosts, ip_addresses, processes, services`), with case-fold and
  basename matching. `hash` and `registry_value` IOCs are reported as **unscored** — the
  producer has no such channel yet. (Precision needs a fully-labeled benign IOC baseline the
  producer doesn't emit; deferred.)
- **Chain reconstruction** — oracle stages joined to `attack_story.attack_chain[]` by
  `technique + phase`; `coverage` = fraction of oracle stages matched; `ordering` = adjacent-pair
  concordance over the run's integer `order`.
- **Verdict band** — scoped verdict vs expected.

Cross-cutting: **AI-degree** (`none` / `AI-present` / `AI-orchestrated`) inferred from documented
Tier-1 integration-artifact signatures (embedded provider keys, local-LLM disk paths like
`~/.ollama/history`, prompts-as-code, LLM-API endpoints) — never writing style; and the honest
`llm_provenance` control (did `gpt-oss:20b` author the seal, or did it fall back to the
deterministic engine).

## Run

```
node scripts/score-image-run.mjs <verdict.json> --oracle <ground-truth.json> [--require-llm]
```

`--require-llm` exits non-zero when the seal came from the deterministic fallback rather than
the LLM agent — the gate to flip on once a model can seal.

## Tests

`node scripts/selftest.mjs` (CI) covers 10 assertions: the captured win-lateral run scores full
on all four axes with `AI-degree = none` and `deterministic-fallback` provenance; the crafted
`ai-present.verdict.json` fixture is flagged `AI-present`; a stripped run drops MITRE/IOC/chain
(regression guard); an empty verdict scores ~0 (negative control); and a reversed chain drops
the ordering score.

## Deferred (Proof B / C)

Installing the ARM64 forensic toolchain and building a real image are separate proofs; see
`docs/forensic-image-benchmark-design.md` (in the dgx-spark-lab repo). This grader is the
scoring substrate they will feed.
