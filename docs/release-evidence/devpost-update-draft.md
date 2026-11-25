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

> Current public evidence is intentionally scoped: the compact EVTX packet proves finding-to-tool-call traceability; Nitroba records 5/5 recall in the local scoring matrix; NIST Hacking Case records 7/14 recall (50%) against a 71% bar on the standard committed runs (5/14 on leaner runs — run-to-run variance disclosed), and the missing artifact classes are published instead of hidden.

## Video Review Note

Use this text:

> Demo video: https://youtu.be/4RQnVden6L8. If a reviewer cannot inspect the video directly, confirm that the primary terminal capture is a clean live run with no fault injection. Any verifier re-dispatch/self-correction clip is optional harness/demo evidence only and must not be counted as organic self-correction.

## Evidence Map

- `43` product tools: `docs/reference/mcp-and-tools.md`.
- Nitroba `5/5` and NIST `7/14` (5/14 on leaner runs): `docs/DATASET.md` and `docs/accuracy-report.md`.
- EVTX trace packet: `docs/release-evidence/evtx-security-log-clear-trace.jsonl` and `docs/release-evidence/evtx-security-log-clear-trace-summary.json`.
