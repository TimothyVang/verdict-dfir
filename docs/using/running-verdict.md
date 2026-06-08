> **Status: ACTIVE.** The canonical operator guide for running VERDICT — the one command, its flags, the three flows, SIFT mode, the live dashboard, and the per-Case output layout.

# Running VERDICT

VERDICT has **one entry point**: `scripts/verdict <evidence>`. Point it at an Observable (a
single image, a `.evtx`, a Velociraptor zip, or a mixed case directory) and it runs the whole
workflow with no human input after launch:

```
preflight (doctor) → build the Rust MCP server if needed → investigate via the typed
MCP pipeline → open the live dashboard at the Case → signed Verdict + report
```

The Verdict word is always one of **`SUSPICIOUS`** / **`INDETERMINATE`** / **`NO_EVIL`** (see
[`../verdict-semantics.md`](../verdict-semantics.md)). Every Finding cites a `tool_call_id` from
the 31 audit-chained product tools (19 Rust + 12 Python) — the only surface sealed into the
manifest. `.mcp.json` registers 5 servers total; 3 are operator-runtime
(`findevil-mcp`, `findevil-agent-mcp`, plus the dashboard/automation helpers) — full table in
[`../reference/mcp-and-tools.md`](../reference/mcp-and-tools.md).

---

## 1. The one command and its flags

```bash
scripts/verdict <evidence> [options]
```

Every flag the launcher actually parses:

| Flag | Effect |
|---|---|
| `<evidence>` (positional) | Path to the Observable. Omit it to use the newest non-placeholder entry already in `evidence/`. |
| `--sift` | Run the DFIR tools inside the SANS SIFT VM over SSH (default: tools on the local host). Requires a one-time `bash scripts/sift-vm-bootstrap.sh`. |
| `--watch` | No path? Block until a file **or** a case folder is dropped into `evidence/`, debounced until the copy finishes, then go. |
| `--no-dashboard` | Do not auto-open the web dashboard. |
| `--skip-build` | Assume `target/release/findevil-mcp` is already built; skip the `cargo build`. |
| `--dry-run` | Print each stage (`doctor`, build, engine argv, dashboard) without running anything. |
| `--unattended` | Forwarded to the engine: auto-resolve Pool A vs. Pool B contradictions to the higher-credibility pool; never pause for analyst input. |
| `--run-summary <path>` | Also write a machine-readable JSON pointer/QA file to `<path>` (see §6). |
| `-- <args...>` | Forward all remaining args verbatim to the engine (`scripts/find_evil_auto.py`). |

Unrecognized `-*` flags (anything not in the table) are forwarded to the engine as-is, so
engine-only flags like `--no-report`, `--signer sigstore`, or `--force-fresh-replay` work
without an explicit pass-through. To be unambiguous, put them after `--`.

Local mode (the default, no `--sift`) is what most operators run; it pins a fresh
`case_id`, writes straight to `tmp/auto-runs/<case-id>/`, and opens the dashboard **live**
before the engine starts so you watch the audit chain land stage by stage.

---

## 2. Flow A — hands-free batch

Give it a path; walk away. Best for a known Observable.

```bash
# Local host (default):
scripts/verdict evidence/DE_1102_security_log_cleared.evtx

# Skip the browser, run unattended (CI / scripted):
scripts/verdict evidence/case.E01 --no-dashboard --unattended

# Already built the Rust server this session:
scripts/verdict evidence/memory.img --skip-build
```

The launcher resolves evidence in this order: explicit arg → newest entry in `evidence/` →
wait for a drop (it blocks unless `--dry-run`).

---

## 3. Flow B — `--watch` drop-a-file

Start the watcher with no path; it blocks until you drop an Observable into `evidence/`.

```bash
scripts/verdict --watch
# … then, from another shell or your file manager:
cp /path/to/base-dc-memory.img evidence/
```

It accepts a single file **or** a whole case folder, and debounces until the (recursive) size
stops growing — so a long `cp` of a multi-GB image won't trigger a half-copied run.

---

## 4. Flow C — interactive (drive it yourself)

Open Claude Code in the repo and run the investigation by hand. Same typed tools, same audit
chain, but you steer each stage.

```bash
claude            # or: scripts/find-evil
```

Then prompt:

```
investigate <path-to-evidence>
```

On session start the agent reads `agent-config/SOUL.md` → `AGENTS.md` → `PLAYBOOK.md` →
`TOOLS.md` → `MEMORY.md` → `HEARTBEAT.md`, then `case_open` → Pool A + Pool B subagents →
`detect_contradictions` → `judge_findings` → `correlate_findings` → `manifest_finalize`.

---

## 5. SIFT mode (`--sift`)

`--sift` does **not** change the workflow — only *where the DFIR tools run*. It swaps the MCP
registry so the two product servers (`findevil-mcp`, `findevil-agent-mcp`) are spawned **inside
the SANS SIFT VM over SSH stdio** instead of on the local host:

1. The launcher requires `.mcp.json.sift` (produced by `bash scripts/sift-vm-bootstrap.sh`).
2. It backs up `.mcp.json` to `.mcp.json.local.bak`, copies `.mcp.json.sift` over `.mcp.json`,
   and restores the original on exit (an `EXIT` trap — safe even on failure).
3. The host `cargo build` is skipped (the Rust server is built inside the VM by the bootstrap).
4. The dashboard opens **after** the post-run sync, since the Case dir is resolved from the
   run summary once the engine returns.

```bash
scripts/verdict --sift /mnt/hgfs/evidence/cases/base-dc/ --unattended
```

VM connection details (`FIND_EVIL_GUEST_IP`, `FIND_EVIL_SSH_KEY`, `FIND_EVIL_GUEST_REPO`, …)
are in [`../reference/environment-variables.md`](../reference/environment-variables.md).

---

## 6. The live dashboard

In local mode the launcher opens the dashboard **before** the engine runs so you watch the
Case build in real time:

- It checks `http://localhost:3000`; if nothing is listening it starts the Next.js dev server
  (`pnpm --filter @findevil/web dev`, logs to `/tmp/verdict-dashboard.log`, ~10s) with
  `FINDEVIL_REPO_ROOT` and `FINDEVIL_DASHBOARD_EXTRA_ROOTS` set so the API accepts the Case path.
- It opens `http://localhost:3000/?case=<url-encoded case dir>` via `xdg-open`.
- `--no-dashboard` skips all of this and prints the Case path instead.

If the dev server is slow to come up, open `http://localhost:3000/?case=<case dir>` manually.

---

## 7. Output layout

Every run writes a self-contained Case directory under `tmp/auto-runs/<case-id>/` (in SIFT mode
it is synced back to the host after the run):

```
tmp/auto-runs/auto-<uuid>/
├── verdict.json              the evidence-bound Verdict + Findings (each cites a tool_call_id + confidence tier)
├── run.manifest.json         Merkle root over canonical tool outputs + signature metadata — verifiable offline
├── manifest_verify.json      offline verification result; check overall == true
├── audit.jsonl               append-only, hash-chained log of every tool call and Finding (prev_hash per record)
├── REPORT.md / .html / .pdf  analyst report: figures, Findings, ATT&CK coverage, timeline, next actions
├── expert_signoff.json       expert-signoff packet / status for customer-release candidates
├── customer_release_gate.final.json  release-gate decision (blockers, warnings)
├── timeline.json / timeline.csv      normalized event timeline exports
└── figures/                  matplotlib figures embedded in the report
```

One line on the load-bearing four:

| File | What it is |
|---|---|
| `verdict.json` | THE answer: the Verdict word, the Findings list, ATT&CK/practitioner coverage, evidence cards, source bibliography, next analyst actions. |
| `run.manifest.json` | The signed manifest — Merkle root + signature metadata. The thing a third party verifies offline. |
| `manifest_verify.json` | The verification result. A passing live test requires `overall: true`. |
| `audit.jsonl` | The hash-chained chain of custody; every `tool_call_id` a Finding cites resolves to a line here. |

The `--run-summary <path>` file is a separate machine-readable pointer (it carries `run_id`,
`case_id`, evidence path, local run directory, output artifact paths, report QA, release-gate /
expert-signoff state, signer, readiness state, blockers, warnings, and the final result). It is
written wherever you point it; if you omit the flag the launcher still writes one to
`tmp/verdict-last-run.json`.

A run is a **live test**: confirm `verdict.json` carries a real Verdict whose Findings cite
`tool_call_id`s, and `manifest_verify.json` reports `overall: true`. An honest
`INDETERMINATE` on a custody-only disk is a PASS — see [`../verdict-semantics.md`](../verdict-semantics.md).

---

## 8. Entry points (one canonical, the rest are plumbing)

| Command | Role |
|---|---|
| `scripts/verdict` | **Canonical.** The one operator command — preflight, build, investigate, dashboard, signed Verdict. |
| `scripts/find-evil-run`, `scripts/find-evil-live` | Deprecated shims kept for muscle memory; they route into `verdict`. |
| `scripts/find_evil_auto.py` (`find-evil-auto`) | The internal headless engine `verdict` drives. Call it directly only for engine-only flags or debugging. |
| `scripts/find-evil-sift` | The SIFT helper invoked under `--sift`; not a separate operator workflow. |
| `claude` / `scripts/find-evil` | Interactive Claude Code session for Flow C (`investigate <path>`). |

Prefer `scripts/verdict` unless you have a specific reason not to. Toolchain prerequisites are
in [`../reference/dependencies.md`](../reference/dependencies.md); the full tool surface is in
[`../reference/mcp-and-tools.md`](../reference/mcp-and-tools.md); all environment variables are
in [`../reference/environment-variables.md`](../reference/environment-variables.md).
