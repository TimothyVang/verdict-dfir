# MCP Servers & Tool Surface — canonical inventory

> **Status: ACTIVE.** This is the single source of truth for *which MCP servers exist*, *which
> tools they expose*, and *what is and is not in the audit chain*. `agent-config/TOOLS.md` is
> the agent read-order catalog of the 46 typed **product** tools; this file is the wider map
> (every registered server + the host/browser MCP). When the two disagree, the tool *counts* in
> both must match — fix the drift, don't pick a winner.

Two numbers that look like a contradiction but aren't:

- **48** = the **product tool surface** (34 Rust + 14 Python). This is the narrow, typed,
  audit-chained verb set the investigation runs on. It does not change lightly.
- **6** = the number of **MCP servers actually registered in `.mcp.json`**. Only the first two
  are product-default and in the audit chain; the other four are non-product conveniences
  (operator-runtime browser/automation + the optional `qmd` memory sidecar).

Neither number contradicts the other: 46 counts *product tools*, 6 counts *registered servers*.

---

## 1. Registered MCP servers (`.mcp.json`)

| # | Server | Transport / command | Role | In audit chain? | Emits Findings? |
|---|---|---|---|---|---|
| 1 | `findevil-mcp` | stdio · `bash scripts/run-mcp-rust.sh` | 34 typed Rust DFIR tools | **Yes** | **Yes** |
| 2 | `findevil-agent-mcp` | stdio · `bash scripts/run-mcp-python.sh` | 14 Python crypto / ACH / memory / ACP / expert tools | **Yes** | **Yes** |
| 3 | `n8n-mcp` | stdio · `npx -y n8n-mcp` (`MCP_MODE=stdio`) | Post-verdict finding-to-action automation (operator-local) | No | No |
| 4 | `playwright` | stdio · `npx -y @playwright/mcp@latest` | Browser automation / dashboard verification | No | No |
| 5 | `puppeteer` | stdio · `npx -y @modelcontextprotocol/server-puppeteer` | Gated-asset (SANS SIFT OVA) browser download during `setup` | No | No |
| 6 | `qmd` | stdio · `bash scripts/run-mcp-qmd.sh` | Optional operator memory sidecar; inert unless `FINDEVIL_ENABLE_QMD=1` and a local `obsidian-mind/` vault are present | No | No |

**Product-default (1–2)** are the only servers whose calls are hash-chained into `audit.jsonl`,
Merkle-rooted, and signed. Every Finding cites a `tool_call_id` from one of these two.

**Non-product (3–6)** are conveniences for the human operator — automation (`n8n-mcp`), browser
tasks (`playwright`/`puppeteer`), and an optional `qmd` dev-memory sidecar. They **never touch
evidence, never append to the audit chain, and never emit a Finding.** `qmd` is launched via
`scripts/run-mcp-qmd.sh`, which resolves Node 22 via nvm and is **inert without Node 22 + QMD** —
it exits cleanly when the optional local vault/toolchain is absent, so a fresh clone / a judge
without the toolchain simply doesn't get it. Seeing six entries in `.mcp.json` is correct, not
malformed.

### SIFT-transport variant — `.mcp.json.sift`

`scripts/find-evil-sift` (and `scripts/verdict --sift`) swap **servers 1 and 2** to an `ssh`
transport that runs the same two binaries inside the SANS SIFT VM (IP/key/repo populated at
runtime from `SIFT_SSH_KEY` / `SIFT_VM_IP` / `GUEST_USER` / `GUEST_REPO_PATH`; default key
`~/.ssh/sift_key`). Servers 3–6 stay host-local. Do **not** hand-edit the IP or key path in
`.mcp.json.sift` — they are rewritten automatically.

### Globally-registered MCP (outside `.mcp.json`)

If configured in the operator's global Claude Code setup, a `chrome-devtools` MCP server can
auto-spawn via `npx -y chrome-devtools-mcp`. It is used for the
session-start "offer to open the dashboard / GitHub / report" behavior. Like the
operator-runtime servers, it is **not** part of the investigation surface.

---

## 2. Product tools — 48 total (34 Rust + 14 Python)

**Invariant: there is no `execute_shell` tool, ever.** This typed surface is the entire verb
set the investigation has. The narrowness *is* the security pitch. The five generic Rust verbs
(`vol_run`, `ez_parse`, `plaso_parse`, `mac_triage`, `cloud_audit`) are **allow-listed
parameterized verbs**, not shells: the plugin/tool/module/parser/provider name is validated
against a fixed allow-list before any argv is built, so an off-list or injection-shaped value is
rejected with a typed error and never reaches a subprocess. The six single-purpose subprocess
wraps (`journalctl_query`, `login_accounting`, `ausearch`, `nfdump_query`, `suricata_eve`,
`indx_parse`) take a typed path and a fixed argv — a hostile path is one inert argv element,
never a flag or a shell fragment.

**Maturity note.** The long-tail verbs `vol_run`, `ez_parse`, `plaso_parse`, `mac_triage`,
`cloud_audit`, `journalctl_query`, `login_accounting`, `ausearch`, `nfdump_query`,
`suricata_eve`, and `indx_parse` are implemented as typed, allow-listed, shell-free tools and
unit-tested against synthetic fixtures, but they have not yet been exercised on real evidence in a
committed case run. The committed sample runs prove the core disk/registry/EVTX/MFT/Prefetch/YARA/
USN/Hayabusa/Sysmon/Zeek/PCAP, `vol_*`, `vel_collect`, and `browser_history` paths.

### `findevil-mcp` — 34 Rust DFIR tools (`services/mcp/src/tools/`)

| Tool | Purpose | Source |
|---|---|---|
| `case_open` | SHA-256 the evidence, issue `case_id`, open the case dir (must be called first) | `case_open.rs` |
| `disk_mount` | Register a read-only disk-mount session for raw/E01 images | `disk.rs` |
| `disk_extract_artifacts` | Copy `$MFT`/Registry/EVTX/Prefetch/… from the mount into the case area; also recovers deleted-but-metadata-intact files (staged under `__deleted__/<inode>/`, reallocated inodes skipped, opt out with `recover_deleted: false`) | `disk.rs` |
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
| `browser_history` | Read visited URLs from a Chrome/Edge `History` or Firefox `places.sqlite` (read-only, in-process via `rusqlite`) | `browser_history.rs` |
| `oe_dbx_parse` | Read an Outlook Express `.dbx` mail/news store — OE-signature-validated, extracts RFC822 `Subject`/`From`/`Newsgroups` headers (in-process; no other parser reads DBX) | `oe_dbx_parse.rs` |
| `thumbcache_parse` | Parse XP `Thumbs.db` (OLE/CFB catalog) and Vista+ `thumbcache_*.db`/`iconcache_*.db` (CMMM) — image-viewed/presence evidence that survives file deletion (in-process, magic-byte detected) | `thumbcache_parse.rs` |
| `hashset_lookup` | NSRL known-good / operator known-bad hash-set lookup — streamed text sets or read-only-immutable SQLite (RDS v3 / generic), parameterized queries only | `hashset_lookup.rs` |
| `vol_run` | Allow-listed Volatility3 plugin verb (the ~40-plugin memory tail in one tool) — `PluginNotAllowed` before argv | `vol_run.rs` |
| `ez_parse` | Allow-listed Eric Zimmerman tool verb (LNK/JumpLists/Amcache/ShimCache/RecycleBin/shellbags/WxT) → CSV rows | `ez_parse.rs` |
| `plaso_parse` | Allow-listed log2timeline parser verb (cross-OS text/binary logs) → normalized timeline events | `plaso_parse.rs` |
| `mac_triage` | Allow-listed mac_apt module verb (macOS Unified Logs/FSEvents/launchd/KnowledgeC/TCC/…) | `mac_triage.rs` |
| `cloud_audit` | Cloud/identity audit-log verb (CloudTrail/Entra/M365/GCP/k8s/VPC) — pure-Rust, normalized envelope | `cloud_audit.rs` |
| `journalctl_query` | Binary systemd journal via `journalctl --file -o json` (Linux host) | `journalctl_query.rs` |
| `login_accounting` | wtmp/btmp login records via `last -F -w` (Linux host; recorded remote host retained) | `login_accounting.rs` |
| `ausearch` | Linux auditd `audit.log` via `ausearch -i -if` (install-first) | `ausearch.rs` |
| `nfdump_query` | NetFlow/IPFIX via `nfdump -r -o json` (no free-text filter; install-first) | `nfdump_query.rs` |
| `suricata_eve` | PCAP → Suricata `eve.json` (install-first) | `suricata_eve.rs` |
| `indx_parse` | NTFS `$I30`/INDX slack via `INDXParse.py` (install-first) | `indx_parse.rs` |

### `findevil-agent-mcp` — 14 Python tools (`services/agent_mcp/findevil_agent_mcp/tools/`)

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
| `accuracy_compare` | Read-only ground-truth accuracy diagnostic (TP/FP/FN, precision/recall/F1, hallucination rate) for a finished Case vs a curated golden — a DIAGNOSTIC, never a Finding (emits at most one non-Finding `accuracy_diagnostic` audit record) | `accuracy_compare.py` |

> The `memory_remember`/`memory_recall` pair is the **in-flow investigation memory** (Hermes
> FTS5, audit-chained). It is distinct from any optional operator-side memory sidecar such as
> `qmd` / the **obsidian-mind dev/operator memory vault** — optional operator memory that may be
> omitted from reduced source checkouts. Don't conflate them: Hermes lives inside cases and the
> audit chain; operator memory (qmd / obsidian-mind) never does.

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
| `sleuthkit` (`fls`/`icat`/`mmls`) | `disk_extract_artifacts` (`.e01`/`.dd` content) | IPL-1.0 / CPL-1.0 | disk stays custody-only |
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
- [`agent-config/TOOLS.md`](https://github.com/TimothyVang/verdict-dfir-beta/blob/main/agent-config/TOOLS.md) — per-tool args/returns (agent read-order).
- [`../architecture.md`](../architecture.md) — the trust boundaries and where the surface sits.
