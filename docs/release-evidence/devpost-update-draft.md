# Devpost Update Draft

Use this if Devpost edits are still open or if an update comment is allowed.

## Replace Tool Count Sentence

Replace the outdated sentence that says the product has thirty-two
schema-validated tools.

With:

> 43 schema-validated product tools (31 Rust DFIR + 12 Python crypto/ACH/memory/ACP/expert tools). The GitHub repo also registers four non-product convenience MCP servers; they do not emit Findings or enter the audit chain.

## Replace Try-It-Out Sample Link

Prefer this link:

`https://github.com/TimothyVang/verdict-dfir/tree/master/docs/release-evidence`

If the existing Devpost link cannot be edited, `docs/sample-run/README.md` now points readers to the current release-evidence packet and fresh-run commands.

## Accuracy Wording

Use this text:

> Current public evidence is intentionally scoped: the compact EVTX packet proves finding-to-tool-call traceability; on the local-runnable corpus 9 of 9 cases pass (aggregate recall 23/27 = 85%, measured 2026-07-01); Nitroba records 5/5 recall; NIST Hacking Case records 10/14 = 71% recall, passing at its 71% bar, and the four missing artifact classes (USB history, deleted email, empty-XP-logon, thumbcache) are published instead of hidden.

## Video Review Note

Use this text:

> Demo video: https://youtu.be/4RQnVden6L8. If a reviewer cannot inspect the video directly, confirm that the primary terminal capture is a clean live run with no fault injection. Any verifier re-dispatch/self-correction clip is optional harness/demo evidence only and must not be counted as organic self-correction.

## Evidence Map

- `43` product tools: `docs/reference/mcp-and-tools.md`.
- Nitroba `5/5` and NIST `10/14 = 71%` (passes at floor; 9/9 local corpus, 23/27 = 85% aggregate): `docs/DATASET.md` and `docs/accuracy-report.md`.
- EVTX trace packet: `docs/release-evidence/evtx-security-log-clear-trace.jsonl` and `docs/release-evidence/evtx-security-log-clear-trace-summary.json`.
