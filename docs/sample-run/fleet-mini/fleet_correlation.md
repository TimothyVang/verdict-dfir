# Fleet correlation report

**Fleet dir:** `fleet-mini`
**Host count:** 3

## Verdict distribution

| Verdict | Count |
|---|---:|
| **INDETERMINATE** | 2 |
| **SUSPICIOUS** | 1 |

## MITRE ATT&CK technique density across the fleet

| Technique | Hosts |
|---|---:|
| T1543.003 | 1 |
| T1047 | 1 |
| T1070.001 | 1 |

## Cross-host process-name correlation

*hypothesis: uncommon process names that appear on ≥2 hosts. Same name across multiple hosts is a much stronger lateral-movement signal than the same name on one host alone — a lead for an analyst to confirm, not a conclusion.*

*No cross-host process correlations found.*

## Temporal clusters

*hypothesis: groups of process creations across multiple hosts that fall within a 60-second window. Tight time clusters spanning ≥2 hosts are a hallmark of automated lateral movement (PsExec waves, WMI execution, scheduled-task chains) — leads for an analyst to confirm, not conclusions.*

*No multi-host temporal clusters within the 60s window.*

## Cryptographic attestation across the fleet

All 3 per-host manifests have Merkle roots; **3 unique values** (all unique — chain integrity intact).

Each per-host manifest is independently verifiable via `manifest_verify`. The fleet correlation report (this file) is **derivative**, not authoritative — it summarizes the per-host manifests but doesn't replace them. A judge / counter-party who wants to verify must verify each `run.manifest.json` individually.

## Recommended next steps for the analyst

1. Triage the SUSPICIOUS-tier hosts first (verdict distribution above).
2. For any cross-host process appearing on ≥3 hosts, pull the binary off disk (via the corresponding host's E01) and YARA-scan it.
3. For temporal clusters spanning ≥3 hosts, build a timeline of the cluster's events and look for the *first* host in the cluster — that's the patient zero candidate.
4. Cross-reference any T1014 (Rootkit) hosts against the disk image's `\Windows\System32\drivers\` for unsigned drivers.

---

## Judge self-score (fleet aggregate)

*No host emitted `kind=judge_selfscore` audit records. This fleet predates commit 94c08dd which wired the selfscore step into find-evil-auto. Re-run any host with the current orchestrator and the records will appear in audit.jsonl + the per-case REPORT.pdf.*

---

*This report was produced by `fleet_correlate.py` as a derivative summary of the fleet's per-host investigations. The authoritative evidence is the set of per-host `run.manifest.json` files in each case directory.*