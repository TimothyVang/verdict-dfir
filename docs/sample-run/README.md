# Sample runs — self-contained, offline-verifiable execution logs

These are real, completed VERDICT investigations committed into the repo so a judge who
**clones without running the tool** still gets traceable agent execution logs (Submission
Requirement #8) and can verify the chain of custody **offline**. Every file here is the
byte-for-byte output of an actual run — nothing was edited, because editing any record would
break the hash chain (which is the point).

Three runs are included. The first shows catching evil head-on; the second and third show the
≥2-artifact-class rule producing CONFIRMED execution findings on the *same* case — once in pure
**local** mode (no SIFT VM) and again under `--sift`, proving the verdict is identical either way:

| Run | Evidence | Verdict | Findings | What it demonstrates |
|---|---|---|---|---|
| [`attack-samples-evtx/`](attack-samples-evtx/) | EVTX attack-sample set | **SUSPICIOUS** | 3 (1 CONFIRMED + 2 `hypothesis:`) | Catching evil head-on: a directly-observed Security **EID 1102 audit-log-clear** (T1070.001) confirmed, with weaker leads honestly held at HYPOTHESIS. |
| [`nist-hacking-case/`](nist-hacking-case/) | NIST CFReDS `SCHARDT.dd` (public domain), **local mode** (Prefetch **+** registry/UserAssist) | **SUSPICIOUS** | 9 (8 CONFIRMED + 1 HYPOTHESIS) | The ≥2-artifact-class rule on the recommended **no-VM path**: with the disk's Prefetch *and* the NTUSER.DAT **UserAssist** hive both parsed on the host (TSK direct-read — no 9 GB SIFT OVA needed), each hacking-tool execution (cain, netstumbler, mirc, ethereal, lookatlan) is corroborated by **two independent artifact classes**, so it escalates to **CONFIRMED**. Each CONFIRMED finding's `derived_from` cites *both* `tool_call_id`s (a `prefetch_parse` and a `registry_query`), so the 2-class claim is greppable, not prose. |
| [`nist-hacking-case-sift/`](nist-hacking-case-sift/) | Same `SCHARDT.dd`, run under `--sift` (Prefetch **+** registry/UserAssist inside the SIFT VM over SSH) | **SUSPICIOUS** | 9 (8 CONFIRMED + 1 HYPOTHESIS) | **Mode parity:** the identical 2-class CONFIRMED escalation, driven inside the SANS SIFT VM over SSH instead of on the host — proving a judge gets the same verdict whether they take the easy local path or the full VM. |

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
- **The two NIST runs share evidence, not a case id.** They are independent investigations of
  `SCHARDT.dd` (one local-mode on the host, one inside the SIFT VM), so their `case_id`s, audit
  chains, and Merkle roots differ — each verifies standalone. Their *verdicts and finding sets*
  match, which is the mode-parity point.
- **The ≥2-class rule cuts both ways.** When only one artifact class is parseable, the same
  correlator holds execution claims at INFERRED/HYPOTHESIS instead of CONFIRMED — the aggregate
  counts are in each run's `verdict.json → findings_summary` (`soul_md_kept` /
  `soul_md_downgraded`); runs produced after 2026-06-09 additionally audit the per-finding
  decisions as a `correlation_outcomes` record.
