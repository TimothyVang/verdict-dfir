# MCP Servers & Tool Surface — canonical inventory

> **Status: ACTIVE.** This is the single source of truth for *which MCP servers exist*, *which
> tools they expose*, and *what is and is not in the audit chain*. `agent-config/TOOLS.md` is
> the agent read-order catalog of the 31 typed **product** tools; this file is the wider map
> (every registered server + the host/browser MCP). When the two disagree, the tool *counts* in
> both must match — fix the drift, don't pick a winner.

Two numbers that look like a contradiction but aren't:

- **31** = the **product tool surface** (19 Rust + 12 Python). This is the narrow, typed,
  audit-chained verb set the investigation runs on. It does not change lightly.
- **5** = the number of **MCP servers actually registered in `.mcp.json`**. Only the first two
  are product-default and in the audit chain; the other three are operator-runtime conveniences.

Neither number contradicts the other: 31 counts *product tools*, 5 counts *registered servers*.

---

## 1. Registered MCP servers (`.mcp.json`)

| # | Server | Transport / command | Role | In audit chain? | Emits Findings? |
|---|---|---|---|---|---|
| 1 | `findevil-mcp` | stdio · `bash scripts/run-mcp-rust.sh` | 19 typed Rust DFIR tools | **Yes** | **Yes** |
| 2 | `findevil-agent-mcp` | stdio · `bash scripts/run-mcp-python.sh` | 12 Python crypto / ACH / memory / ACP / expert tools | **Yes** | **Yes** |
| 3 | `n8n-mcp` | stdio · `npx -y n8n-mcp` (`MCP_MODE=stdio`) | Post-verdict finding-to-action automation (operator-local) | No | No |
| 4 | `playwright` | stdio · `npx -y @playwright/mcp@latest` | Browser automation / dashboard verification | No | No |
| 5 | `puppeteer` | stdio · `npx -y @modelcontextprotocol/server-puppeteer` | Gated-asset (SANS SIFT OVA) browser download during `setup` | No | No |

**Product-default (1–2)** are the only servers whose calls are hash-chained into `audit.jsonl`,
Merkle-rooted, and signed. Every Finding cites a `tool_call_id` from one of these two.

**Operator-runtime (3–5)** are convenience servers for the human operator (automation, browser
tasks). They **never touch evidence, never append to the audit chain, and never emit a
Finding.** A Codex/Claude operator seeing five entries in `.mcp.json` is correct — it is not
malformed.

### SIFT-transport variant — `.mcp.json.sift`

`scripts/find-evil-sift` (and `scripts/verdict --sift`) swap **servers 1 and 2** to an `ssh`
transport that runs the same two binaries inside the SANS SIFT VM (IP/key/repo populated at
runtime from `SIFT_SSH_KEY` / `SIFT_VM_IP` / `GUEST_USER` / `GUEST_REPO_PATH`; default key
`~/.ssh/sift_key`). Servers 3–5 stay host-local. Do **not** hand-edit the IP or key path in
`.mcp.json.sift` — they are rewritten automatically.

### Globally-registered MCP (outside `.mcp.json`)

Per the host `~/.claude/settings.json`, a `chrome-devtools` MCP server (`cloakbrowser`) is
registered globally and auto-spawns via `npx -y chrome-devtools-mcp`. It is used for the
session-start "offer to open the dashboard / GitHub / report" behavior (CLAUDE.md §0). Like the
operator-runtime servers, it is **not** part of the investigation surface.

---

## 2. Product tools — 31 total (19 Rust + 12 Python)

**Invariant: there is no `execute_shell` tool, ever.** This typed surface is the entire verb
set the investigation has. The narrowness *is* the security pitch.

### `findevil-mcp` — 19 Rust DFIR tools (`services/mcp/src/tools/`)

| Tool | Purpose | Source |
|---|---|---|
| `case_open` | SHA-256 the evidence, issue `case_id`, open the case dir (must be called first) | `case_open.rs` |
| `disk_mount` | Register a read-only disk-mount session for raw/E01 images | `disk.rs` |
| `disk_extract_artifacts` | Copy `$MFT`/Registry/EVTX/Prefetch/… from the mount into the case area | `disk.rs` |
| `disk_unmount` | Unmount a disk-mount session, mark it unmounted in the ledger | `disk.rs` |
| `evtx_query` | Parse `.evtx` with EventID/limit filtering (in-process `evtx` crate) | `evtx_query.rs` |
| `prefetch_parse` | Execution evidence from Windows Prefetch (MAM + SCCA) | `prefetch_parse.rs` |
| `mft_timeline` | NTFS `$MFT` timeline with `$SI`/`$FN` MAC times | `mft_timeline.rs` |
| `registry_query` | Read keys/values from offline Registry hives | `registry_query.rs` |
| `yara_scan` | In-process YARA scan (`yara-x`, no subprocess) | `yara_scan.rs` |
| `usnjrnl_query` | Stream NTFS USN Journal change records, reason-filtered | `usnjrnl_query.rs` |
| `hayabusa_scan` | Sigma sweep over an EVTX dir (subprocess to `hayabusa`) | `hayabusa_scan.rs` |
| `sysmon_network_query` | Sysmon network events (EID 3) from EVTX | `sysmon_network_query.rs` |
| `zeek_summary` | Summarize Zeek TSV logs (conn/dns/http/tls) | `zeek_summary.rs` |
| `pcap_triage` | Triage PCAP via fixed `tshark`/`zeek` argv | `pcap_triage.rs` |
| `vol_pslist` | Volatility3 `windows.pslist` (active-list processes) | `vol_pslist.rs` |
| `vol_psscan` | Volatility3 `windows.psscan` (pool-scan; DKOM cross-check) | `vol_psscan.rs` |
| `vol_psxview` | Volatility3 `windows.psxview` (cross-view process compare) | `vol_psxview.rs` |
| `vol_malfind` | Volatility3 `windows.malfind` (injected code, T1055) | `vol_malfind.rs` |
| `vel_collect` | Run a Velociraptor artifact via subprocess, stream rows | `vel_collect.rs` |

### `findevil-agent-mcp` — 12 Python tools (`services/agent_mcp/findevil_agent_mcp/tools/`)

| Tool | Purpose | Source |
|---|---|---|
| `audit_append` | Append one record to the hash-chained audit log | `audit_append.py` |
| `audit_verify` | Replay the audit chain offline (every `prev_hash` link) | `audit_verify.py` |
| `manifest_finalize` | Build the rs_merkle tree, sign, write `run.manifest.json` | `manifest_finalize.py` |
| `manifest_verify` | Offline verify: chain → Merkle root → signature presence | `manifest_verify.py` |
| `verify_finding` | Re-run a Finding's cited tool call; confirm output SHA-256 still matches | `verify_finding.py` |
| `detect_contradictions` | Surface Pool A vs Pool B disagreements before judging | `detect_contradictions.py` |
| `judge_findings` | Credibility-weighted Pool A + Pool B merge | `judge_findings.py` |
| `correlate_findings` | Enforce the ≥2-artifact-class rule; downgrade single-source claims | `correlate_findings.py` |
| `memory_remember` | Hermes FTS5 cross-case memory write (CONFIRMED-only) | `memory_remember.py` |
| `memory_recall` | Hermes FTS5 cross-case memory query (BM25 × decay) | `memory_recall.py` |
| `pool_handoff` | IBM-ACP structured role-to-role handoff (audit record) | `pool_handoff.py` |
| `expert_miss_capture` | Record an expert's pre-release PDF edit into the miss ledger | `expert_miss_capture.py` |

> The `memory_remember`/`memory_recall` pair is the **in-flow investigation memory** (Hermes
> FTS5, audit-chained). It is distinct from the **obsidian-mind dev/operator memory vault** —
> see [`../runbooks/obsidian-mind-memory.md`](../runbooks/obsidian-mind-memory.md). Don't
> conflate them: Hermes lives inside cases and the audit chain; obsidian-mind never does.

---

## 3. External DFIR tools (subprocess-only, never linked)

These back the Rust tools but are **invoked as subprocesses** so the Apache-2.0 tree stays
license-clean. Full version/license/expected-failure matrix in
[`dependencies.md`](dependencies.md). The one exception is **`yara-x`**, which is the in-process
Rust crate behind `yara_scan` (not a subprocess).

| Backs | Tool(s) | License | Missing → |
|---|---|---|---|
| `volatility3` | `vol_pslist/psscan/psxview/malfind` | Volatility Software License (BSD-2-style) | BinaryNotFound |
| `hayabusa` | `hayabusa_scan` | AGPL-3.0 | BinaryNotFound |
| `velociraptor` | `vel_collect` | Apache-2.0 | BinaryNotFound |
| `tshark` | `pcap_triage` (preferred) | GPL-2.0 | falls back to zeek, else env-limit |
| `zeek` | `zeek_summary`, `pcap_triage` (fallback) | BSD-3-Clause | env-limit |
| `chainsaw` | optional EVTX hunting (not a core tool) | Elastic-2.0 | n/a |
| `pandoc` | report HTML/PDF render (`render_report.py`) | GPL-2.0 | HTML/PDF render skipped |

Binary resolution order for the Rust server: `$VOLATILITY_BIN` / `$HAYABUSA_BIN` /
`$VELOCIRAPTOR_BIN` / `$TSHARK_BIN` first, then PATH. A missing binary is an **environment
limitation reported as BinaryNotFound**, never evidence-absence.

---

## 4. See also

- [`dependencies.md`](dependencies.md) — version pins, licenses, expected-failure matrix.
- [`environment-variables.md`](environment-variables.md) — the full env-var surface.
- [`../../agent-config/TOOLS.md`](../../agent-config/TOOLS.md) — per-tool args/returns (agent read-order).
- [`../architecture.md`](../architecture.md) — the trust boundaries and where the surface sits.
