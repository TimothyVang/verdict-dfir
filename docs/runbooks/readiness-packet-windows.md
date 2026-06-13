# Runbook: Readiness Packet (Windows)

**Status: ACTIVE**
**Script:** `scripts/readiness-gate.ps1`

The readiness gate is the pre-submission validation step that confirms the product is
working end-to-end and packages the artifacts a human expert reviews before the Devpost
upload. It runs on Windows because the SIFT VM is VMware-based and the full flow needs
the host's VMware Workstation.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Windows with PowerShell 5.1+ | All invocations use `-ExecutionPolicy Bypass` |
| VMware Workstation | Required for Full mode SIFT transport (`scripts/verdict <path> --sift` invokes the helper); not needed for PacketOnly |
| `uv` on PATH | `pip install uv` |
| `cargo` on PATH | Rust 1.88 (`rust-toolchain.toml`) |
| `gh` CLI authenticated | `gh auth login` |
| `claude` CLI on PATH | For Full mode; inherits Claude Code subscription credentials |

---

## Three invocation modes

### Full mode — one command from a clean tree

Runs local build/smokes, drives the same internal automation engine used by `scripts/verdict`, validates the
resulting manifest, checks report QA + expert signoff, packages artifacts, and writes
`readiness-packet.zip`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/readiness-gate.ps1 `
    -Mode Full `
    -EvidencePath <path-to-evidence-inside-SIFT-VM> `
    -RunL1Docker
```

Artifacts land in `tmp/readiness-gates/<run-id>/packet/`. Summary JSON is written
at `tmp/readiness-gates/<run-id>/readiness-summary.json` and copied into the
packet. The packet manifest is `tmp/readiness-gates/<run-id>/packet/readiness-packet-manifest.json`.

**Fixed `-RunId` rerun** (refreshes packet, reuses existing run artifacts):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/readiness-gate.ps1 `
    -Mode Full `
    -RunId <existing-run-id> `
    -ExistingRunDir tmp/auto-runs/<case-id>
```

If a `<run-id>-build` child run already exists, the gate creates a fresh
`<run-id>-build-<timestamp>` run instead of failing.

### PacketOnly mode — validate and package an existing run

Fastest for iterating on an already-completed run. Does not run evidence or claim full
submission readiness.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/readiness-gate.ps1 `
    -Mode PacketOnly `
    -ExistingRunDir tmp/auto-runs/<case-id>
```

### POSIX check-only (no ZIP produced)

Strict check that prints `SUBMISSION_READY` or `READINESS_BLOCKED` without packaging.
Useful in CI or on Linux/Mac.

```bash
EVIDENCE_RUN_DIR=<run-dir> \
L1_DOCKER_STATUS=passed \
L1_DOCKER_LOG=<log-file-with-READINESS_L1_PASS> \
bash scripts/readiness-gate.sh
```

---

## Readiness states

| State | Meaning | How to unblock |
|---|---|---|
| `READY_FOR_EXPERT_REVIEW` | Full mode passed all checks. Ready for human expert sign-off — **not** customer-releasable yet. | Nothing blocked; proceed to expert review. |
| `PACKET_READY_FOR_EXPERT_REVIEW` | PacketOnly mode passed all checks. Packet assembled but full-flow claim not made. | Run Full mode to get `READY_FOR_EXPERT_REVIEW`. |
| `SUBMISSION_READY` | POSIX check-only gate passed. No ZIP; confirms artifacts are consistent. | For ZIP + expert-review packet, run the PowerShell Full mode. |
| `READINESS_BLOCKED` | One or more blockers. The `readiness-summary.json` `blockers[]` array names each one. | See "Unblocking" section below. |

---

## Unblocking `READINESS_BLOCKED`

Blockers are printed to stderr during the run and collected in `readiness-summary.json`.

| Blocker pattern | Fix |
|---|---|
| Missing L1 evidence / L1 Docker status not `passed` | Pass `-RunL1Docker` in Full mode, or set `L1_DOCKER_STATUS=passed` env var in POSIX mode only after confirming the L1 Docker run actually passed |
| `manifest_verify` failed | The `audit.jsonl` or `run.manifest.json` in the run directory is corrupt or tampered; re-run evidence collection from scratch |
| Report QA failed | Open the `report_qa` section of `readiness-summary.json` for the failing checks; fix the investigation report, then rerun the gate or `scripts/verdict` |
| Expert signoff absent or not recorded | The human expert must run the signoff step — the internal automation engine marks `expert_signoff_state` as `required`; see `agent-config/EXPERT.md` for the signoff protocol |
| `customer_releasable: false` | This is expected and correct — `READINESS_BLOCKED` in this context means the flag was unexpectedly set to `true` by automation. Do not flip it to `true` without an explicit policy decision. |
| Build skipped / `SkipBuild` flag set + no prior binary | Either remove `-SkipBuild` or provide a pre-built binary |

---

## Output artifacts

After a successful Full-mode run:

```
tmp/readiness-gates/<run-id>/
├── logs/
├── packet/
│   ├── audit.jsonl                         ← append-only hash chain
│   ├── run.manifest.json                   ← manifest to upload with submission
│   ├── manifest_verify.json                ← recomputed offline verification
│   ├── verdict.json                        ← Verdict + traced Findings
│   ├── expert_signoff.json                 ← expert-review state
│   ├── customer_release_gate.final.json    ← customer-release gate state
│   ├── REPORT.html                         ← rendered report artifact
│   ├── REPORT.pdf                          ← included when PDF rendering succeeds
│   ├── REPORT.md                           ← included when the run emitted it
│   ├── evidence_inventory.json             ← included when emitted
│   ├── timeline.json / timeline.csv        ← included when emitted
│   ├── figures/                            ← included when emitted
│   ├── readiness-summary.json              ← machine-readable gate outcome
│   ├── readiness-packet-manifest.json      ← packet files + checksums
│   └── logs/                               ← validator logs copied when present
├── readiness-summary.json                  ← same summary, outside the ZIP source
└── readiness-packet.zip                    ← ZIP of packet/ contents
```

---

## Key flags

| Flag | Default | Purpose |
|---|---|---|
| `-Mode` | `Full` | `Full` or `PacketOnly` |
| `-EvidencePath` | `$env:EVIDENCE_PATH` | Path to evidence file/dir inside SIFT VM (Full mode) |
| `-ExistingRunDir` | `$env:EVIDENCE_RUN_DIR` | Skip evidence run; validate existing run directory |
| `-RunId` | auto-generated | Fix the run ID for reruns; gate refreshes packet contents |
| `-Signer` | `ed25519` | `ed25519` (real local signature, verifies offline), `sigstore` (identity + Rekor transparency log), or `stub` (explicit test placeholder) |
| `-ForceFreshReplay` | off | Force replay even if a cached run exists |
| `-RunL1Docker` | off | Also run L1 Docker gate during Full mode |
| `-SkipBuild` | off | Skip `cargo build` (use pre-built binary) |
| `-SkipPackage` | off | Skip ZIP packaging (check-only) |
