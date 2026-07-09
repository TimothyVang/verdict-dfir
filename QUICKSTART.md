# VERDICT DFIR — Quickstart

For the project pitch + claims, see [README.md](README.md). For the full doc map, see [`docs/README.md`](docs/README.md).

---

## Quickstart in 3 steps

```bash
git clone --depth 1 https://github.com/TimothyVang/verdict-dfir-beta.git verdict && cd verdict
bash scripts/setup                    # installs the product toolchain, common DFIR tools, browser helpers, and both MCP servers, then runs doctor
scripts/verdict <path-to-evidence>    # investigate -> live dashboard -> signed verdict + report
```

**Prefer to drive it with Claude Code?** Drop your evidence into **`evidence/`**, open `claude`, and
type **`investigate evidence/`**. (Or hands-free in a session: `/verdict <path>` runs the pipeline
and attempts SIFT VM setup when disk evidence needs it.)

No evidence yet? `bash scripts/fetch-fixtures.sh` stages public datasets (into `fixtures/`). A view-only Google Drive artifact folder is also available at <https://drive.google.com/drive/folders/1j4nPm3vjAcRwVdKOauIVc8yurxoADhOv?usp=drive_link>; CLI users can download it with their own authenticated rclone Google Drive remote:

```bash
rclone config create gdrive drive scope drive
rclone copy --drive-root-folder-id 1j4nPm3vjAcRwVdKOauIVc8yurxoADhOv gdrive: ./verdict-dfir-artifacts --progress
scripts/verdict ./verdict-dfir-artifacts/network-captures/nitroba/nitroba.pcap
```

Canonical install detail — prerequisites and how to verify — is in [INSTALL.md](INSTALL.md).

**Everything below is "going deeper"** — environment choices (SIFT VM vs. local) and the full
run-mode catalog.

---

## 1. Pick your environment (one-time, ~15 min)

### Path A — SIFT VM (recommended; the reference forensic environment)

**The one-command way** — install local prerequisites, attempt the gated OVA fetch via Playwright,
and build the VM when the download succeeds:

```bash
bash scripts/setup --with-sift
```

If the headless fetch can't complete (the SANS page changed, you're offline, a hypervisor is
missing), it falls back cleanly and tells you the manual step below — and local-host mode (Path B)
still works meanwhile. In a `claude` session, typing `setup` does the same and can adapt to page
changes.

**Manual OVA download (fallback, one-time, ~9.3 GB).** The SANS SIFT Workstation OVA is **not** shipped in this repo (it is SANS-licensed, gitignored as `*.ova`, and far larger than GitHub's file limit). Download it yourself:

1. Go to **<https://www.sans.org/tools/sift-workstation/>**
2. Scroll to the **VM** option and download the OVA (~9.3 GB).
3. Save it to the repo root as `sift-2026.03.24.ova` (or point `OVA_PATH` at wherever you saved it).

```bash
# From the repo root, on Windows with VMware Workstation installed
# and the OVA saved as sift-2026.03.24.ova in the repo root:
bash scripts/sift-vm-bootstrap.sh
```

This converts the OVA, boots the VM headless, installs Rust + DFIR tools inside, sets up the SSH transport, and rewrites `.mcp.json.sift` to point at the running VM. Runs ~15 min on first invocation; subsequent runs detect existing state and skip.

> **Hypervisor note:** `scripts/verdict <path> --sift` invokes the SIFT helper under the hood. It supports **VMware Workstation** (primary, via `vmrun`/`ovftool`) or **KVM/libvirt** (Linux fallback — `scripts/sift-vm-bootstrap.sh` auto-installs qemu/libvirt and imports the OVA). **VirtualBox is not supported.** If you only have VirtualBox, use VMware or KVM/libvirt, or run local-host mode (Path B).

### Path B — Local Windows host (faster iteration)

```bash
# Install the four DFIR-tool binaries on Windows (one-time):
winget install Volatility3 || pip install volatility3
winget install Hayabusa  # or download from github.com/Yamato-Security/hayabusa/releases
winget install Velociraptor  # or github.com/Velocidex/velociraptor/releases
# YARA-X is already in our crate; no separate install needed.

# That's it — `.mcp.json` points at local subprocesses by default.
```

---

## 2. Choose a run mode

### Option 2C — the `/verdict` skill (turnkey, recommended)

The shortest path. In a Claude Code session (`claude` in the repo), type:

```
/verdict <path-to-evidence>
```

The skill is the turnkey path: it checks/builds the MCP servers, attempts SIFT VM setup when disk
evidence needs it, auto-uses `--sift` when the VM is reachable, runs the parallel investigation to
a signed Verdict, attempts optional n8n/grounding workflows only when enabled or already available,
opens the dashboard + report, and prints the Verdict plus the workflow status. Full reference:
[docs/using/running-verdict.md §0](docs/using/running-verdict.md). (Loaded at session start — if you
just pulled it, start a fresh `claude` session.)

### Option 2A — Interactive Claude Code session (best for exploration)

```bash
# Local mode:
scripts/find-evil
# or:
claude

# SIFT-VM evidence run:
scripts/verdict <path-to-evidence> --sift
```

`.mcp.json` (or `.mcp.json.sift`, swapped automatically) tells Claude Code to spawn both MCP servers — `findevil-mcp` (Rust, 34 typed DFIR tools) and `findevil-agent-mcp` (Python, 14 typed crypto/ACH/memory/ACP/expert-feedback tools).

In the session, prompt:

> investigate `<path-to-evidence>`

The agent reads `agent-config/SOUL.md` → `AGENTS.md` → `PLAYBOOK.md` → `TOOLS.md` → `MEMORY.md` → `HEARTBEAT.md` at session start, then drives the playbook tool sequence for that evidence type.

### Option 2B — `verdict` (the one command, no human input)

```bash
scripts/verdict <evidence> [--sift] [--no-dashboard] [--unattended]
```

`verdict` runs the whole workflow: preflight → investigate → open the live dashboard at the case →
signed verdict + report. Add `--sift` to run the DFIR tools inside the SANS SIFT VM.

Examples:

All direct `/mnt/...` SIFT evidence paths must be mounted read-only in the guest.

```bash
# Memory image:
scripts/verdict --sift /mnt/hgfs/evidence/extracted/base-dc/base-dc-memory.img --unattended

# Single EVTX from a read-only SIFT-visible evidence mount:
scripts/verdict --sift /mnt/hgfs/evidence/single-evtx/Security.evtx --unattended

# Disk image (read-only mount/extract where prerequisites support it; otherwise custody-only):
scripts/verdict --sift /mnt/hgfs/evidence/disk-images/base-dc-cdrive.E01 --unattended

# Host evidence root mounted read-only inside SIFT; skips multi-GB SCP staging:
FINDEVIL_SIFT_HOST_EVIDENCE_ROOT=/path/to/evidence \
FINDEVIL_SIFT_GUEST_EVIDENCE_ROOT=/mnt/verdict-evidence \
scripts/verdict /path/to/evidence/disk-images/base-dc-cdrive.E01 --sift --unattended

# Mixed case directory (memory, EVTX, disk artifacts, network logs, Velociraptor zips):
scripts/verdict --sift /mnt/hgfs/evidence/cases/base-dc/ --unattended

# Same run, plus a machine-readable automation summary outside evidence paths:
scripts/verdict --sift /mnt/hgfs/evidence/cases/base-dc/ --unattended --run-summary tmp/run-summary.json

# Velociraptor collection zip:
scripts/verdict --sift /mnt/hgfs/evidence/velociraptor/base-dc.zip --unattended
```

What it does in one command (no interactive prompts):

1. Detects evidence type from the file extension or inventories a mixed case directory
2. Opens both MCP servers inside the SIFT VM via SSH stdio
3. case_open or case inventory -> tool sequence per type -> audit chain -> judge -> correlator -> manifest_finalize. Raw disk image support is bounded: auto mode attempts read-only mount/extract through local Sleuth Kit/libewf or SIFT, otherwise it records custody-only limitations and next actions.
4. Synthesizes Pool A (persistence-biased) and Pool B (exfil-biased) findings deterministically from tool outputs
5. Writes `verdict.json` with the verdict (`SUSPICIOUS` / `NO_EVIL` / `INDETERMINATE` — see [`docs/verdict-semantics.md`](docs/verdict-semantics.md)), case completeness, ATT&CK/practitioner coverage, normalized timeline data, evidence-card data, source bibliography, and next analyst actions
6. Generates a fully-templated PDF investigation report (figures + findings + ATT&CK/practitioner coverage + timeline + visual evidence cards + source bibliography + chain-of-custody attestation)
7. If `--run-summary <path>` is set, writes a JSON pointer/QA file containing `run_id`, `case_id`, evidence path, local run directory, output artifact paths, report QA, release-gate/expert-signoff state, signer, readiness state, blockers, warnings, and final result. Keep this path outside evidence directories; `tmp/run-summary.json` is the recommended local default.

Output (on host):
```
tmp/auto-runs/auto-<uuid>/
├── audit.jsonl
├── run.manifest.json
├── manifest_verify.json
├── verdict.json
├── expert_signoff.json
├── customer_release_gate.final.json
├── timeline.json
├── timeline.csv
├── REPORT.md / .html / .pdf
└── figures/
```

`run-summary.json` is written wherever you pass `--run-summary`; it is not copied into the case directory unless you choose a path there. `scripts/verdict` delegates to the internal engine for this run; call the engine directly only when debugging engine-only flags.

Run with `--no-report` to skip PDF rendering (saves ~5 seconds).

### Option 2D — Fleet investigation (entire host inventory)

When the case is "we have N memory images, find all the evil," chain three scripts:

```bash
python scripts/fleet_investigate.py [--limit N] [--skip BASENAMES]
python scripts/fleet_correlate.py [tmp/fleet-runs/<fleet-id>]
python scripts/render_fleet_report.py [tmp/fleet-runs/<fleet-id>]
```

Output: `tmp/fleet-runs/fleet-<timestamp>/FLEET_REPORT.{md,html,pdf}` plus per-host artifacts and four matplotlib figures. Cross-host process correlation filters known-benign enterprise binaries via `COMMON_WIN_PROCS` in `scripts/fleet_correlate.py` — see [`docs/false-positives.md`](docs/false-positives.md) "Fleet cross-host correlation" for what is and isn't filtered.

---

## 3. (If interactive) the agent drives the playbook

You'll see:

1. `case_open` — SHA-256 of the evidence (chain of custody starts here)
2. **Pool A** (persistence) and **Pool B** (exfil) subagents fork in parallel and run their tool sequences
3. Findings emerge tagged with `tool_call_id`, MITRE ATT&CK technique, and confidence (CONFIRMED / INFERRED / HYPOTHESIS)
4. `detect_contradictions` surfaces Pool A vs Pool B disagreements **before** the judge merges
5. `judge_findings` + `correlate_findings` apply credibility weighting + the SOUL.md ≥2 artifact-class rule
6. `manifest_finalize` builds the Merkle tree, records signature metadata, and writes `run.manifest.json` — terminal step under Amendment A5. Local/offline automation can use a clearly identified stub signer; customer-release candidates require non-stub signing plus separate transparency-log validation.

Output lands at `~/.findevil/cases/<case_id>/` (or inside the VM at `/home/sansforensics/find-evil/tmp/<case_id>/` in SIFT-VM mode).

Verifying a manifest someone else produced: drive `manifest_verify` from the agent_mcp server, or call `findevil_agent.crypto.manifest.verify_manifest` directly. Recipe + expected output: [`docs/cryptographic-attestation.md`](docs/cryptographic-attestation.md) §"How a third party verifies offline."

---

## Where to read next

For the full doc map (every file with status badge + one-line purpose), see [`docs/README.md`](docs/README.md). High-traffic entries when something goes wrong:

- "Every `verdict` flag, run mode, and output file" → [`docs/using/running-verdict.md`](docs/using/running-verdict.md) (canonical). Entry points: `scripts/verdict` is canonical; `find-evil-run`/`find-evil-live` are deprecated shims; `find-evil-auto` is the internal engine; `find-evil-sift` is the SIFT helper.
- "What must I install, and what version?" → [`docs/reference/dependencies.md`](docs/reference/dependencies.md) + run `bash scripts/doctor.sh`.
- "Something failed — what does this error mean?" → [`docs/troubleshooting.md`](docs/troubleshooting.md) (every failure mode → its code-enforced detector → the fix command).
- "How do I avoid false positives?" → [`docs/false-positives.md`](docs/false-positives.md)
- "What does the agent actually do?" → [`agent-config/PLAYBOOK.md`](agent-config/PLAYBOOK.md)
- "What evidence is available?" → [`docs/DATASET.md`](docs/DATASET.md)
- "What if a tool is missing?" → The agent returns `BinaryNotFound -32602`. Install the binary OR set the env var pointing at it (e.g. `VOLATILITY_BIN=/path/to/vol`).
- "I changed something — how do I prove the app still works?" → run a **live test**: `scripts/verdict evidence/<file>` (e.g. an evidence file you supply under `evidence/`, or a fixture staged by `scripts/fetch-fixtures.sh`), then confirm `tmp/auto-runs/<case-id>/verdict.json` has a real Verdict with `tool_call_id`-cited Findings and `manifest_verify.json` `overall=true`. A live test — not a smoke run — is the verification standard.
- "I changed something — how do I confirm L1 CI will be happy?" → `bash scripts/run-all-smokes.sh` on POSIX/Git Bash, or `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run-all-smokes.ps1` on native Windows. These are CI-predictor smoke runners, not live tests: they predict what L1 runs but don't exercise a real investigation. The scripts print the current smoke tally; runtime depends on Rust cache and shell startup. If native Windows Git Bash startup is slow enough to trip launcher syntax-check timeouts, set `FINDEVIL_LAUNCHER_SMOKE_BASH_TIMEOUT_SECONDS` to a larger value before rerunning.
- "How do I produce a review packet?" → `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/readiness-gate.ps1 -Mode Full -EvidencePath <path-inside-sift-vm> -RunL1Docker`. The gate writes `readiness-summary.json` and `readiness-packet.zip` under `tmp/readiness-gates/<run-id>/`, with packet/readiness-packet-manifest.json listing copied artifacts. Fixed `-RunId` reruns refresh generated packet contents and may create a fresh timestamped build child run. A passing gate prints `READY_FOR_EXPERT_REVIEW`, not customer-ready; a failing gate prints `READINESS_BLOCKED` and lists blockers in `readiness-summary.json`.

---

## Anti-patterns

* **Don't** trust HYPOTHESIS-tier findings without verification. The agent prefixes them with the literal word "hypothesis:" — those are leads, not facts.
* **Don't** skip the synthetic-benign baseline (`goldens/synthetic-benign/`) — running on benign data first calibrates your false-positive floor.
* **Don't** modify evidence files. The chain-of-custody invariant is filesystem-enforced; any write to `/evidence/<case_id>/` from outside the agent invalidates the manifest's claims.
* **Don't** add `execute_shell` or any tool that takes arbitrary commands. The "narrow typed surface" is the architectural pitch; widening it forfeits that.

---

## End-of-investigation checklist

0. [ ] Live test passed: `scripts/verdict` produced `verdict.json` and `manifest_verify.json` `overall=true`
1. [ ] `manifest_verify.json` or the `manifest_verify` MCP/library result returns `overall=True`
2. [ ] Findings table reviewed; CONFIRMED-tier findings traced back to their `tool_call_id` in `audit.jsonl`
3. [ ] Contradictions resolved or explicitly flagged in the report
4. [ ] Cross-host corroboration done (if multi-host case)
5. [ ] Synthetic-benign baseline run produced zero findings
6. [ ] Report rendered to PDF or HTML in the case output directory
7. [ ] Readiness packet created and reviewed if this is a release/customer-review candidate

If all relevant checks are complete, you're done. If any are skipped, document the reason in the report's §8 (Limitations).
