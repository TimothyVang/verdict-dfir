# Evidence Answer Keys

This maps the local `evidence/` drop zone to scoreable VERDICT answer keys.

Evidence remains read-only and gitignored. These answer keys contain only expected findings and high-level artifact hints; they do not copy raw evidence, event XML, packets, disk files, memory contents, cookies, or private document text.

## Scoreable Local Cases

| Evidence path | Answer key | Product verdict polarity | Notes |
|---|---|---|---|
| `evidence/nitroba.pcap` | `goldens/nitroba/expected-findings.json` | `SUSPICIOUS` | Existing public Digital Corpora network golden. The JSON uses the legacy evil scoring label `CONFIRMED_EVIL`. |
| `evidence/SCHARDT.dd` | `goldens/nist-hacking-case/expected-findings.json` | `SUSPICIOUS` | Existing NIST CFReDS Hacking Case golden. The JSON uses the legacy evil scoring label `CONFIRMED_EVIL`; disk prerequisites affect recall. |
| `evidence/DE_1102_security_log_cleared.evtx` | `goldens/security-log-cleared/expected-findings.json` | `SUSPICIOUS` | Single confirmed Security EID 1102 log-clear finding. |
| `evidence/attack-samples/` | `goldens/evtx-attack-samples/expected-findings.json` | `SUSPICIOUS` | EVTX folder: log clear plus WMI and service-install leads. |
| `evidence/cases/win-lateral-movement/` | `goldens/win-lateral-movement/expected-findings.json` | `INDETERMINATE` | EVTX-only WMI plus service-install leads; single artifact class keeps confidence scoped. |
| `evidence/cases/mini-fleet/hosts/host-01/` | `goldens/service-install-spoolfool/expected-findings.json` | `INDETERMINATE` | Per-host score for the service-install leg of the mini fleet. |
| `evidence/cases/mini-fleet/hosts/host-02/` | `goldens/wmi-execution/expected-findings.json` | `INDETERMINATE` | Per-host score for the WMI execution leg of the mini fleet. |
| `evidence/cases/mini-fleet/hosts/host-03/` | `goldens/security-log-cleared/expected-findings.json` | `SUSPICIOUS` | Per-host score for the log-clear leg of the mini fleet. |

## Live-Run-Only Evidence

| Evidence category | Status | Why no committed answer key |
|---|---|---|
| Single memory images from uncleared SANS-style corpora | Live-run calibration only | Use live-run manifest, citation, and coverage gates; do not publish a recall key until provenance and expected facts are cleared. |
| Heavy disk+memory pairs from uncleared SANS-style corpora | Pending manual walkthrough | Do not publish expected private facts until a cleared analyst walkthrough exists. |
| Background decks or operator briefs | Background only | Operator context is not parser evidence and should not become a scoring key. |
| Private split-disk or collection case folders | Pending manual walkthrough | Keep any temporary key under `tmp/local-goldens/`; never convert limited parser coverage into `NO_EVIL`. |
| Large SRL-style fleet corpora | Live-run-only by design | Use live-run manifest/citation gates and fleet reports instead of committed recall scoring unless the case README explicitly permits a golden. |

For private or uncleared evidence, keep any temporary key under `tmp/local-goldens/<case-id>/expected-findings.json` and pass it explicitly to the scorer. Do not commit it.

## Score Commands

Run one case at a time; do not score the mixed `evidence/` root as one case.

```bash
bash scripts/verdict evidence/DE_1102_security_log_cleared.evtx --no-dashboard --unattended --run-summary tmp/security-log-cleared-summary.json
python scripts/score-recall.py tmp/auto-runs/<case-id> --golden goldens/security-log-cleared

bash scripts/verdict evidence/attack-samples --no-dashboard --unattended --run-summary tmp/attack-samples-summary.json
python scripts/score-recall.py tmp/auto-runs/<case-id> --golden goldens/evtx-attack-samples

bash scripts/verdict evidence/cases/win-lateral-movement/ --no-dashboard --unattended --run-summary tmp/win-lateral-movement-summary.json
python scripts/score-recall.py tmp/auto-runs/<case-id> --golden goldens/win-lateral-movement

bash scripts/verdict evidence/cases/mini-fleet/ --no-dashboard --unattended
python scripts/score-recall.py <host-01-run-dir> --golden goldens/service-install-spoolfool
python scripts/score-recall.py <host-02-run-dir> --golden goldens/wmi-execution
python scripts/score-recall.py <host-03-run-dir> --golden goldens/security-log-cleared
```

`evidence/cases/mini-fleet/` triggers fleet mode and writes per-host run summaries under `tmp/fleet-runs/<fleet-id>/`; the current recall scorer expects a single case directory with `verdict.json`, so score mini-fleet one host run at a time.

If `scripts/score-recall.py` sees a run verdict of `INDETERMINATE`, it treats that as honest scoped uncertainty. A definite `SUSPICIOUS` or `NO_EVIL` must match the answer-key polarity.
