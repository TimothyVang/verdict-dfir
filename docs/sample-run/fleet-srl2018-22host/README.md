# `fleet-srl2018-22host/` — the 22-host fleet rollup (the demo's fleet scene)

The cross-host correlation behind the demo video's fleet beat: VERDICT run **host by host
across a 22-host enterprise** (the SANS SRL-2018 memory fleet), then correlated for activity
that spans machines.

**Headline numbers (from `fleet_correlation.json`, reproducible below):**
- **22 hosts** investigated, every one **INDETERMINATE** — honest: memory alone is a single
  artifact class, so nothing cleared the ≥2-class bar for a definite call.
- **74 cross-host process correlations**, **53 multi-host temporal clusters**.

## The claim the video makes — and where to find it

> *"six machines running the exact same admin tool at the exact same second."*

That is the largest temporal cluster in `fleet_correlation.json`, and it is exact:

| Tool | Hosts (6) | Timestamp |
|---|---|---|
| `Autorunsc.exe` (Sysinternals Autoruns, CLI) | `base-rd-04`, `base-rd-05`, `base-wkstn-01`, `base-wkstn-02`, `base-wkstn-03`, `base-wkstn-04` | `2018-08-15T17:10:32Z` (window: 0.0s) |

```
# find it yourself
python3 -c "import json; c=json.load(open('docs/sample-run/fleet-srl2018-22host/fleet_correlation.json')); \
print([ (e['host'], e['name'], e['create_time']) for cl in c['temporal_clusters'] \
if (cl.get('host_count') or 0)==6 for e in cl['events'] ])"
```

Six machines spawning the same admin/recon binary in the same second is a lateral-movement
signal — one operator (or script) sweeping the fleet. VERDICT surfaces it as a **cross-host
correlation**, not a per-host finding, which is exactly the value a fleet view adds.

## Honest scope of this committed artifact

- This is the **cross-host correlation rollup** (`fleet.json`, `fleet_correlation.json`,
  `FLEET_REPORT.md`). The 22 per-host case directories for *this historical run* were not
  retained, so per-host manifests are not committed here, and the rollup's Merkle-aggregation
  line reads `0/0` (it predates the `fleet_correlate` fix that reads roots from each host's
  manifest).
- For a fleet with **per-host ed25519 manifests that verify offline and aggregate to N/N
  unique Merkle roots**, see the companion [`../fleet-mini/`](../fleet-mini/) (3 hosts, 3/3
  unique roots, each `manifest_verify`-true). Together they show the capability end to end:
  the small fleet proves the crypto, this one proves the scale and the real correlation.
