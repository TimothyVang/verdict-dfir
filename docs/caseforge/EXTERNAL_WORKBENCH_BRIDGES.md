# External Workbench Bridges — caseforge-core

> caseforge is headless. It bridges to external examiner workbenches; it does
> not depend on them, and it does not embed their GUI logic.

## 1. Posture: Headless Controller

caseforge-core is a headless DFIR controller. It runs the same on a Linux
laptop, a DGX/Spark box, a SIFT workstation, a server, or a CI fixture runner —
with **no examiner GUI dependency**. All capability is driven through the CLI,
the SDK, VERDICT MCP tools, and the agent loop.

Staying headless is a deliberate architectural choice: it keeps the controller
portable, scriptable, CI-runnable, and free of workbench-specific coupling.

## 2. Bridge, Don't Depend

An examiner may still use a GUI workbench. caseforge's relationship to any such
workbench is a **bridge**, not a dependency:

- caseforge produces portable, verifiable outputs — structured findings and the run artifacts (`verdict.json`, `coverage_manifest.json`, `run.manifest.json`, `manifest_verify.json`, `audit.jsonl`).
- An external workbench can consume those outputs as evidence-backed, custody-verified inputs to its own review process.
- The bridge flows outputs **outward**; the controller does not reach inward to a workbench's GUI, case DB, or internal modules.

This keeps the trust boundary clean: the workbench reviews what caseforge
produced without caseforge inheriting the workbench's coupling or attack surface.

## 3. Explicitly Excluded

Per the project scope, caseforge does **not** build, embed, or depend on:

| Excluded | Reason |
|----------|--------|
| Autopsy | Not a dependency; no engine coupling to it. |
| Autopsy MCP / modules / case-DB adapters | No case-DB or module integration. |
| Examiner GUI workbench logic | Engine stays headless. |
| Generic shell MCP | Attack-surface reduction. |
| Generic filesystem MCP | Attack-surface reduction. |
| Docker / Kubernetes MCP | Out of scope. |
| Broad GitHub admin MCP | Out of scope. |
| Real evidence in GitHub Actions | CI runs synthetic/public fixtures only. |

## 4. What A Bridge May Look Like (Non-Prescriptive)

If integration with a workbench is desired later, it is built as a one-way
export/consumer of caseforge's already-verified artifacts — never as an inward
dependency on the workbench's GUI or database. The custody guarantees
(`tool_call_id` + `output_sha256` + manifest verification) travel with the
artifacts, so a downstream workbench can independently confirm that findings are
tool-backed rather than model-asserted.
