# Fleet analysis — the 3-stage pipeline

> **Status: ACTIVE.** Operator guide for investigating a whole evidence corpus at once: queue
> per-host Verdict runs, correlate Findings across hosts, and render one fleet-level report.

When you have a directory of memory images — one per host in a compromised estate — you do not
want to open 22 Cases by hand. The fleet pipeline runs a per-host investigation for every image,
then looks for the signals that only appear *across* hosts (the same uncommon process on many
machines, near-simultaneous process creations, MITRE technique spread), and rolls everything up
into a single `FLEET_REPORT`.

**It is one command.** Point `scripts/verdict` at the case root — a folder with the whole-case
layout (`hosts/`, `disks/`) is auto-detected as a fleet (or force it with `--fleet`):

```bash
# Local fleet (per-host verdicts -> correlation -> FLEET_REPORT), resumable —
# re-run the same command and completed hosts are skipped:
scripts/verdict evidence/cases/srl-2018

# Same, with the per-host DFIR tools running inside the SANS SIFT VM:
scripts/verdict evidence/cases/srl-2018 --fleet --sift
```

Under the hood that chains three stages. Each stage reads the previous stage's output from the
same `tmp/fleet-runs/<fleet-id>/` directory, so you never have to thread paths by hand — and you
can still run any stage individually:

| Stage | Script | Reads | Writes |
|---|---|---|---|
| 1. Investigate | `scripts/fleet_investigate.py` | `.img` files in the SIFT VM | `fleet.json`, `fleet-summary.md`, per-host case dirs |
| 2. Correlate | `scripts/fleet_correlate.py` | `fleet.json` + each `verdict.json` / `psscan.json` | `fleet_correlation.{json,md}` |
| 3. Render | `scripts/render_fleet_report.py` | `fleet_correlation.json` | `FLEET_REPORT.{md,html,pdf}` + `figures/` |

All three default to the most recent fleet under `tmp/fleet-runs/`, so a clean sequence needs no
arguments after stage 1. Everything is derivative of the per-host artifacts — the authoritative
evidence is each host's own `run.manifest.json`, verifiable offline via `manifest_verify` (see
`docs/reference/mcp-and-tools.md`).

---

## Prerequisites

- **The SIFT VM must be reachable.** Stage 1 SSHes into the VM to enumerate evidence and runs
  the internal automation engine per host. It reads the VM coordinates from environment variables (see
  `docs/reference/environment-variables.md`):
  - `FIND_EVIL_GUEST_IP` (default `192.168.197.143`)
  - `FIND_EVIL_GUEST_USER` (default `sansforensics`)
  - `FIND_EVIL_SSH_KEY` (default `~/.ssh/sift_key`)
- **Evidence layout.** Stage 1 enumerates `*.img` files under `/mnt/hgfs/evidence/extracted/`
  inside the VM. The host name for each image is taken from its **parent directory name** — so
  `/mnt/hgfs/evidence/extracted/base-mail/memory.img` is reported as host `base-mail`.
- **matplotlib is required for stage 3.** `render_fleet_report.py` imports matplotlib at module
  load and will not run without it. Install per `docs/reference/dependencies.md`. (Stages 1 and 2
  are pure-stdlib and need no extra packages.)

### Staging evidence into the VM (zero-copy) + first-run fixes

The enumerator only sees images already at `/mnt/hgfs/evidence/extracted/<host>/*.img` **inside the
guest** — SIFT mode never copies evidence in. The guest disk is usually small (~25 GB free), so do
not `scp` a multi-GB corpus; **share it** instead:

1. Build a host-side **hardlink** tree — `tmp/sift-fleet-evidence/extracted/<host>/memory.img`
   (hardlinks cost no disk and are visible through HGFS; symlinks are not).
2. `vmrun -T ws enableSharedFolders <vmx>` then
   `vmrun -T ws addSharedFolder <vmx> evidence "$PWD/tmp/sift-fleet-evidence"`.
3. In the guest: `sudo mkdir -p /mnt/hgfs && sudo vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other`,
   then verify `ls /mnt/hgfs/evidence/extracted`.
4. Run with `FIND_EVIL_GUEST_IP=<actual guest IP>` — the `192.168.197.143` default drifts; read the
   live IP from `.mcp.json.sift` or `vmrun -T ws getGuestIPAddress <vmx> -wait`.

Known first-run fixes (all shipped): the internal automation engine resolves `python3` (not `python`);
`render_fleet_report.py` resolves `pandoc`/`chrome` from PATH (override via `PANDOC_BIN`/`CHROME_BIN`).
If `fleet_correlate.py` reports **0 cross-host correlations despite populated runs**, the guest's
Volatility symbol cache is unwritable — `psscan.json` will be empty (`[]`); make
`/opt/volatility3/.../symbols` writable (`sudo chmod -R a+rwX`) and re-run.

---

## Stage 1 — `fleet_investigate.py`

Walks the VM's evidence root, and for every `.img` it finds (smallest first), spawns the
same internal engine used by `scripts/verdict` and captures the
resulting Verdict. Sequential by default to avoid VM RAM contention; the Volatility symbol cache
makes every image after the first cheaper.

### Flags

| Flag | Effect |
|---|---|
| `--dry-run` | List the images that *would* be investigated (host, size, path) and exit. No Cases opened. |
| `--limit N` | Investigate only the first `N` hosts (smallest-image-first ordering). |
| `--skip BASENAMES` | Comma-separated host basenames to skip, e.g. `--skip base-mail,base-av` to drop the big ones. Matched against the parent-directory host name. |

### Run it

```bash
# See what is out there first — no Cases opened
python scripts/fleet_investigate.py --dry-run

# Investigate the 5 smallest hosts as a warm-up
python scripts/fleet_investigate.py --limit 5

# Full fleet, skipping the two largest images
python scripts/fleet_investigate.py --skip base-mail,base-av
```

### What lands

A new fleet directory is stamped per run: `tmp/fleet-runs/fleet-<UTC-timestamp>/` (e.g.
`fleet-20260608T142233Z`). Inside:

- `fleet.json` — the per-host summary, **rewritten after every host** so a crash mid-fleet never
  loses completed work. Each entry records `host`, `evidence_path`, `verdict`, `case_id`,
  `case_dir`, `findings_summary`, `manifest_path`, `merkle_root`, and `elapsed_sec`.
- `fleet-summary.md` — a human-readable rollup written when the fleet finishes: Verdict
  distribution, per-host Finding counts (CONFIRMED / INFERRED / HYPOTHESIS), contradiction counts,
  and a per-host `case_id` / Merkle-root table.

Each per-host Case lives in its **own** `tmp/auto-runs/auto-<uuid>/` directory (pointed to by
`case_dir` in `fleet.json`) and carries its own `audit.jsonl`, `run.manifest.json`,
`verdict.json`, and — because stage 1 passes `--no-report` — no per-host PDF yet. Per-host status
values you may see instead of a Verdict word: `error`, `no_verdict`, `verdict_unreadable`,
`timeout`, `exception` (each per-host run is capped at 1800s).

---

## Stage 2 — `fleet_correlate.py`

Reads `fleet.json`, then loads each host's `verdict.json` (and `psscan.json` if the Case dir has
one) and looks for cross-host patterns no single Case can see.

### Argument

| Argument | Effect |
|---|---|
| `fleet_dir` (positional, optional) | The fleet directory to correlate. Defaults to the most recent under `tmp/fleet-runs/`. |
| `--temporal-window N` | Seconds for the temporal-cluster window (default `60`). |

### Run it

```bash
# Correlate the most recent fleet
python scripts/fleet_correlate.py

# Or point at a specific fleet
python scripts/fleet_correlate.py tmp/fleet-runs/fleet-20260608T142233Z
```

### What it correlates

- **Cross-host process names.** Any uncommon `ImageFileName` appearing on **≥2 distinct hosts**.
  Common-OS noise is filtered out by the built-in `COMMON_WIN_PROCS` benign list — core Windows
  processes (`svchost.exe`, `lsass.exe`, …), VMware Tools, and the McAfee/Trellix endpoint stack
  the SRL-2018 fleet ships by default. Names are compared after lowercasing and **truncating to
  14 chars**, matching the width of Volatility's `EPROCESS.ImageFileName` field, so a truncated
  psscan name like `VGAuthService.` still matches the canonical `VGAuthService.exe`. Sysinternals
  tools (PsExec, Autorunsc) are deliberately **not** in the benign list, so a fleet-wide run of
  them still surfaces for the analyst.
- **Temporal clusters.** Groups of process creations across **≥2 hosts** that fall inside the
  temporal window — the time fingerprint of automated lateral movement (PsExec waves, WMI chains).
- **MITRE technique density.** Distinct-host count per technique (a host that emits `T1014` from
  both pools still counts once).
- **Verdict distribution** and **Merkle-root uniqueness** (every per-host manifest should have a
  unique root).

### What lands

- `fleet_correlation.json` — structured cross-host findings.
- `fleet_correlation.md` — the human-readable correlation report with a "Recommended next steps"
  section for the analyst.

---

## Stage 3 — `render_fleet_report.py`

Reads `fleet_correlation.json`, generates matplotlib figures, and renders the polished
`FLEET_REPORT`.

### Argument

| Argument | Effect |
|---|---|
| `fleet_dir` (positional, optional) | The fleet directory to render. Defaults to the most recent under `tmp/fleet-runs/`. |

It will refuse to run if `fleet_correlation.json` is missing — run stage 2 first.

### Run it

```bash
python scripts/render_fleet_report.py
```

### What lands

In the same fleet directory:

- `figures/verdict_distribution.png` — Verdict bar chart (SUSPICIOUS red, INDETERMINATE orange,
  NO_EVIL green).
- `figures/mitre_density.png` — technique-by-host horizontal bars.
- `figures/cross_host_processes.png` — top-25 cross-host process names, coloured by host spread
  (≥5 hosts red, 3–4 orange, 2 blue).
- `figures/temporal_clusters.png` — scatter of clustered process creations, only when temporal
  clusters exist.
- `FLEET_REPORT.md` — the report, embedding the figures above.
- `FLEET_REPORT.html` — standalone, self-contained (rendered via pandoc when available).
- `FLEET_REPORT.pdf` — produced via headless Chrome when present; written atomically so a PDF open
  in a viewer is not clobbered.

---

## The full sequence

```bash
python scripts/fleet_investigate.py --skip base-mail,base-av   # stage 1
python scripts/fleet_correlate.py                              # stage 2 (latest fleet)
python scripts/render_fleet_report.py                          # stage 3 (latest fleet)
```

Everything for that fleet now sits under `tmp/fleet-runs/<fleet-id>/`.

---

## How to read `FLEET_REPORT`

Open `FLEET_REPORT.pdf` (or `.html`) and work top-down:

1. **Header line** — hosts investigated, the SUSPICIOUS / INDETERMINATE / NO_EVIL split, the count
   of cross-host process correlations and temporal clusters, and a one-line cryptographic-integrity
   check (all Merkle roots unique = chain integrity intact).
2. **Verdict distribution** — the **SUSPICIOUS hosts are your priority queue.** Open each one's
   `verdict.json` and (if you want a per-host PDF) re-run `scripts/verdict` on that image without
   report-suppression flags.
3. **MITRE density** — if a `pslist`=0 / `psscan`>0 divergence (`T1014`) shows up on a large
   fraction of the fleet, the report deliberately reframes it as a **HYPOTHESIS**: high fleet
   prevalence argues for a shared acquisition-smear / kernel-global read failure, not N
   coordinated rootkits. Confirm or dismiss per host with ≥2 on-disk artifact classes before
   asserting `T1014`.
4. **Cross-host processes** — names on ≥4 hosts are called out by name. Pull the binary off any
   one host's disk image, YARA-scan, and hash it.
5. **Temporal clusters** — trace each cluster back to its **first** event; that host is the
   patient-zero candidate. Cross-reference the cluster times against EVTX logon events (Type 3
   Network / Type 10 RDP) on the destination hosts.
6. **Cryptographic attestation** — the fleet report is **derivative**. To actually verify, run
   `manifest_verify` against each per-host `run.manifest.json` individually — the fleet rollup
   summarizes those manifests, it does not replace them.

---

## See also

- `docs/reference/mcp-and-tools.md` — the 45 audit-chained product tools (32 Rust + 13 Python) and
  `manifest_verify`. (`.mcp.json` registers 6 servers in total; 4 are non-product.)
- `docs/reference/dependencies.md` — installing matplotlib and the rest of the toolchain.
- `docs/reference/environment-variables.md` — `FIND_EVIL_GUEST_IP` / `_GUEST_USER` / `_SSH_KEY`
  and the rest of the SIFT VM coordinates stage 1 depends on.
