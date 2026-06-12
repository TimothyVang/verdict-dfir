# `fleet-mini/` — a committed multi-host fleet run (per-host crypto, offline-verifiable)

A real three-host fleet, built from the public **attack-sample EVTX** set (one log per
host), run through the whole-case fleet pipeline and committed so a judge can verify the
**cross-host cryptographic integrity** without running anything.

| Host | Evidence (real, public) | Verdict | Per-host Merkle root | `manifest_verify` |
|---|---|---|---|---|
| `host-01` | `LM_Remote_Service02_7045.evtx` (lateral movement — service install) | INDETERMINATE | `1d8b5e19…` | ✓ ed25519 verified |
| `host-02` | `LM_WMI_4624_4688_TargetHost.evtx` (WMI lateral movement) | INDETERMINATE | `0cfadfd2…` | ✓ ed25519 verified |
| `host-03` | `DE_1102_security_log_cleared.evtx` (anti-forensics — log clear) | **SUSPICIOUS** | `67dc6f4a…` | ✓ ed25519 verified |

**Cross-host cryptographic integrity: 3/3 unique Merkle roots.** Each host sealed its own
independent run — different `case_id`, audit chain, and Merkle root — with a real ed25519
signature, and `fleet_correlate` confirms all three roots are distinct. (One host being
forged or replayed would collapse that count; independence is the property a fleet needs.)

## Why this exists

The fleet rollup used to report `0/0` Merkle roots because `manifest_finalize` runs *after*
`verdict.json` is written, so the root lives only in each host's `run.manifest.json` — and
the aggregator was reading `verdict.json`. Fixed in `scripts/fleet_correlate.py`
(`_host_merkle_root` falls back to the manifest); this run is the regression artifact.

## Verify it yourself, offline

```
# re-derive every per-host chain and finding (no deps beyond Python 3)
scripts/trace-finding docs/sample-run/fleet-mini/hosts/host-03

# re-run the cross-host correlation from the committed per-host runs
python3 scripts/fleet_correlate.py docs/sample-run/fleet-mini
#   -> cryptographic_attestation: 3/3 unique Merkle roots
```

## Files

- `fleet.json` — per-host verdict table (repo-relative `case_dir` per host).
- `fleet_correlation.json` / `fleet_correlation.md` — cross-host rollup + the 3/3 Merkle check.
- `hosts/<host>/` — each host's lean run: `audit.jsonl`, `run.manifest.json`,
  `manifest_verify.json`, `verdict.json`. Each verifies offline on its own.

This is the **capability proof** for the fleet pipeline. The headline 22-host enterprise
rollup from the demo (74 cross-host process correlations, 53 temporal clusters, including
the six-host `Autorunsc.exe` same-second cluster) lives in
[`../fleet-srl2018-22host/`](../fleet-srl2018-22host/).
