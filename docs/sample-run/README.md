# Sample runs — self-contained, offline-verifiable execution logs

These are real, completed VERDICT investigations committed into the repo so a judge who
**clones without running the tool** still gets traceable agent execution logs (Submission
Requirement #8) and can verify the chain of custody **offline**. Every file here is the
byte-for-byte output of an actual run — nothing was edited, because editing any record would
break the hash chain (which is the point).

Two runs are included because they show the two halves of the agent's epistemic discipline:

| Run | Evidence | Verdict | Findings | What it demonstrates |
|---|---|---|---|---|
| [`attack-samples-evtx/`](attack-samples-evtx/) | EVTX attack-sample set | **SUSPICIOUS** | 3 (1 CONFIRMED + 2 `hypothesis:`) | Catching evil head-on: a directly-observed Security **EID 1102 audit-log-clear** (T1070.001) confirmed, with weaker leads honestly held at HYPOTHESIS. |
| [`nist-hacking-case/`](nist-hacking-case/) | NIST CFReDS `SCHARDT.dd` (public domain) | **INDETERMINATE** | 9 (8 INFERRED + 1 HYPOTHESIS) | Anti-overclaim discipline: 8 hacking tools (cain, netstumbler, mirc, ethereal, lookatlan) recovered from Prefetch are labeled **INFERRED, not CONFIRMED** — Prefetch alone is one artifact class, and an execution claim needs ≥2. The verdict stays INDETERMINATE rather than overstating coverage. |

## Files in each run (lean set)

- `audit.jsonl` — the hash-chained, append-only execution log (every `tool_call_start` /
  `tool_call_output` / `finding_approved` / verifier action; each line carries `prev_hash` + `line_hash`).
- `run.manifest.json` — Merkle root over the audit leaves + signature bundle.
- `manifest_verify.json` — the offline-verification result recorded at run time.
- `verdict.json` — the final verdict and every Finding (each citing a `tool_call_id`).
- `REPORT.md` — the human-readable investigative narrative.
- `evidence_inventory.json` (attack-samples only) — artifact classes touched.

The heavy render artifacts (`REPORT.pdf`, `REPORT.html`, `figures/`, `timeline.*`) are omitted
to keep the tree light; they regenerate from a live run.

## Verify it yourself, offline

The manifest's embedded `audit_log_path` points at the original run directory, so pass the
committed log explicitly as an override. In a Claude Code session in this repo (the
`findevil-agent-mcp` server auto-spawns), call the `manifest_verify` tool:

```
manifest_verify(
  manifest_path  = "docs/sample-run/nist-hacking-case/run.manifest.json",
  audit_log_path = "docs/sample-run/nist-hacking-case/audit.jsonl",
)
```

Both runs return `overall: true` — `audit_chain_ok`, `merkle_root_ok`, `leaf_count_ok`, and
`signature_present` all pass. No network, no trusted third party (FRE 902(14) self-authentication).

Or, with **nothing but a Python 3 interpreter** (no MCP server, no venv), re-verify the
hash-chained audit log from scratch and trace every finding in one command:

```
scripts/trace-finding docs/sample-run/nist-hacking-case
```

`trace-finding` re-canonicalizes every audit line and replays every `prev_hash` link (it exits
non-zero on a single flipped bit), confirms each declared Merkle leaf resolves to an audit
record, and prints the chain below. `manifest_verify` additionally rebuilds the rs_merkle root
and checks the signature bundle.

## Trace any finding to the tool execution that produced it

Worked example (`attack-samples-evtx/`):

```
Finding  f-A-evtx-audit-log-cleared   (confidence: CONFIRMED)
   └─ cites tool_call_id  tc-002
        └─ audit.jsonl seq 4  tool_call_start  tool = evtx_query
           audit.jsonl seq 5  tool_call_output output_hash = 3d3dd694…
              └─ both tc-002 and the finding_id are leaves in run.manifest.json (8 leaves)
```

So the verdict word ← Finding ← `tool_call_id` ← audit record ← Merkle leaf ← signed manifest,
end to end. `scripts/trace-finding <run-dir> [finding_id]` prints exactly this chain for every
finding (or one), and exits non-zero if any finding fails to resolve.

## Honest caveats

- **Signer is the stub signer** (`extra.signer = "stub"`). The hash chain and Merkle root verify
  fully offline; `signature_present` confirms a bundle is attached, but these sample runs are not
  signed with the real Sigstore/Fulcio+Rekor keyless signer. A production run with a real Sigstore
  signature is a separate artifact.
- **Absolute paths are left intact** (`/home/sansforensics/SCHARDT.dd`, etc.) on purpose — they are
  hashed into the chain, so rewriting them would break verification. They are run-host paths, not
  secrets.
- **The NIST run is deliberately INDETERMINATE.** It is the standard for *honest coverage*, not a
  miss: the agent recovered the hacking tools but declined to escalate Prefetch-only execution to
  CONFIRMED. See `nist-hacking-case/REPORT.md`.
