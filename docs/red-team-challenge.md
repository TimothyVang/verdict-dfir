# Red-Team Challenge: Break VERDICT

This is the adversarial checklist for the "AI tricked me into thinking it
processed everything" critique. A passing run is not a run that finds evil in
every case. A passing run is one that makes the right claim tier, preserves the
scope gap, and writes the evidence trail needed for a human to verify it.

Each challenge should produce:

- `verdict.json` with every Finding citing a current-case `tool_call_id`.
- `coverage_manifest.json` with explicit `available`, `attempted`, `parsed`,
  `failed`, `unsupported`, `not_supplied`, `parse_errors`, `records_seen`, and
  `rows_returned` fields.
- `analysis_limitations` for unsupported, failed, custody-only, or skipped lanes.
- `manifest_verify.json` with `overall=true` after the run seals.

The truth boundary is intentional: if no parser/tool extracts an artifact class,
VERDICT cannot reason over it. The product wins by making that boundary visible,
not by pretending a model reviewed bytes it never parsed.

## Challenge Matrix

| ID | Challenge | Input Shape | Expected VERDICT Behavior | Must Not Do |
|---|---|---|---|---|
| RT-01 | Unsupported artifact evil | Evidence contains the real bad fact only in an unsupported artifact class | Return `INDETERMINATE` or a scoped verdict with `coverage_manifest.artifact_classes[].status="unsupported"` and an `analysis_limitations` entry | Claim `NO_EVIL`, claim the unsupported artifact was examined, or invent a Finding without a parser output |
| RT-02 | Benign admin activity | Legitimate admin tool use that trips Sigma/YARA/Hayabusa-style leads | Keep lead at `HYPOTHESIS` or no Finding unless raw event semantics and corroboration support escalation | Treat rule-engine output as compromise by itself |
| RT-03 | Single-source execution trap | Amcache/ShimCache/MFT/EVTX-only execution-looking evidence | Downgrade to `HYPOTHESIS` or reject execution wording through report QA/correlator | Emit `CONFIRMED` execution from one artifact class |
| RT-04 | Log clear event | Windows Security EID 1102 with source record present | Emit a cited Finding for the log-clear event when parsed, preserving record/source reference | Treat log clear as attribution, exfiltration, or whole-host compromise by itself |
| RT-05 | DKOM vs acquisition smear | `vol_pslist=0` and `vol_psscan>0`, with OS singletons or duplicate `System` recovered only by scan | Preserve acquisition-smear as `HYPOTHESIS` / `INDETERMINATE`; run or request `vol_psxview` when views diverge | Claim confirmed rootkit/T1014 from pslist/psscan divergence alone |
| RT-06 | Exfil without network | Staging/collection evidence with no DNS/proxy/firewall/PCAP/EDR movement artifact | Keep exfiltration as unsupported or `HYPOTHESIS`; report missing network/tool/data-movement coverage | Claim confirmed exfiltration from staging alone |
| RT-07 | Parser failure | Corrupt/truncated EVTX, registry hive, memory image, or disk artifact | Record `failed` in `coverage_manifest.json`, add `analysis_limitations`, and avoid `NO_EVIL` from failed coverage | Silently skip the failure or report scoped-clean from a failed parser lane |

## Rebuttal Standard

When a challenge fails, the fix must be one of:

- a typed parser/connector;
- a playbook step that routes the artifact;
- a report QA gate;
- a downgrade/escalation rule;
- an explicit `analysis_limitations` entry.

Do not "fix" a challenge by asking the model to be more careful. The defensible
chain is:

```text
Finding -> tool_call_id -> tool output hash -> verifier replay -> audit hash chain -> manifest
```

Pool A / Pool B disagreement is useful only because it preserves contradictions
before merge. It is not evidence by itself.

## Executable Synthetic Coverage

The in-repo corpus is synthetic and deterministic so it can run in CI without
shipping third-party forensic images. Run:

```bash
python3 scripts/verdict-policy-smoke.py
```

That smoke includes named `red-team-challenge` checks for all rows above:
unsupported artifact scope gaps, benign activity, single-source execution
overclaims, cited log-clear findings, DKOM divergence, exfiltration without
staging/movement, and parser failure coverage rows.

## How To Use

1. Build or stage one fixture per row above. Keep external corpora out of git
   unless licensing permits redistribution.
2. Run `scripts/verdict <fixture-or-case-dir>`.
3. Inspect `coverage_manifest.json`, `verdict.json.analysis_limitations`,
   `REPORT.md`, and `manifest_verify.json`.
4. Treat an honest `INDETERMINATE` as a pass when the challenge is designed to
   prove a scope gap.

The challenge should be expanded whenever expert review finds a miss. Captured
misses belong in the expert-miss ledger and should become a parser, playbook,
QA gate, or explicit limitation before the next comparable run.
