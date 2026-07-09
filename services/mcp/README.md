# findevil-mcp

Typed Rust MCP server for Find Evil! per the public architecture contract.

**Authoritative design:** `docs/architecture.md`.
**Invariants:** `CLAUDE.md` §"Non-negotiable invariants".

## Status

| Component | Status |
|---|---|
| Workspace + crate scaffold | ✅ |
| All 32 typed DFIR tools | ✅ shipped |
| Hand-rolled JSON-RPC 2.0 stdio server (MCP 2024-11-05) | ✅ in `src/server.rs` |
| End-to-end stdio smoke (`scripts/rust-mcp-smoke.py`) | ✅ all 32 tools dispatch over the wire |
| M2 sigstore + rs_merkle integration | partial (rs_merkle live; sigstore lives in `services/agent_mcp/`) |

## Quick start

```sh
# From the repo root:
cargo build --workspace --release --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
```

## Tool surface (32/32 shipped)

Per Spec #2 §6 (which enumerates 11) plus memory cross-validation, disk mount/extract session-resource tools, browser history, allow-listed long-tail wrappers, and Linux/network/NTFS triage additions — see CLAUDE.md "Spec/code divergences" for the rationale. All tools are registered in `src/tools/mod.rs`, advertised in `tools/list`, and dispatchable via `tools/call`. Each successful response carries `_meta.output_sha256`.

| Tool | Module | Backing | Pool |
|---|---|---|---|
| `case_open` | `tools/case_open.rs` | in-process: `sha2`, `uuid` | n/a |
| `disk_mount` | `tools/disk.rs` | fixed subprocess wrappers / mock mode | A/B (disk setup) |
| `disk_extract_artifacts` | `tools/disk.rs` | in-process copy from mounted read-only view | A/B (disk setup) |
| `disk_unmount` | `tools/disk.rs` | fixed subprocess wrappers / mock mode | A/B (disk cleanup) |
| `evtx_query` | `tools/evtx_query.rs` | in-process: `evtx = 0.11.2` | A |
| `prefetch_parse` | `tools/prefetch_parse.rs` | in-process: `frnsc-prefetch + forensic-rs` | A (execution) |
| `mft_timeline` | `tools/mft_timeline.rs` | in-process: `mft = 0.6.1` | A (timeline) |
| `registry_query` | `tools/registry_query.rs` | in-process: `frnsc-hive = 0.13.4` | A (persistence) |
| `browser_history` | `tools/browser_history.rs` | in-process: `rusqlite` (vendored SQLite) | A/B (browser artifact) |
| `yara_scan` | `tools/yara_scan.rs` | in-process: `yara-x = 1.12.0` | B (malware/IOC) |
| `usnjrnl_query` | `tools/usnjrnl_query.rs` | in-process: `usnjrnl-forensic = 0.6.0` | A/B (filesystem changes) |
| `hayabusa_scan` | `tools/hayabusa_scan.rs` | subprocess: `hayabusa` (AGPL) | A (Sigma rules) |
| `vol_pslist` | `tools/vol_pslist.rs` | subprocess: `volatility3` (BSD-2) | A (active-list processes) |
| `vol_psscan` | `tools/vol_psscan.rs` | subprocess: `volatility3` (BSD-2) | A (EPROCESS pool scan) |
| `vol_psxview` | `tools/vol_psxview.rs` | subprocess: `volatility3` (BSD-2) | A (process-view cross-check) |
| `vol_malfind` | `tools/vol_malfind.rs` | subprocess: `volatility3` (BSD-2) | A/B (code injection) |
| `vol_run` | `tools/vol_run.rs` | allow-listed subprocess: `volatility3` plugin | A/B (memory long tail) |
| `ez_parse` | `tools/ez_parse.rs` | allow-listed subprocess: Eric Zimmerman tools | A (Windows artifact long tail) |
| `plaso_parse` | `tools/plaso_parse.rs` | allow-listed subprocess: `log2timeline`/Plaso | A/B (timeline long tail) |
| `mac_triage` | `tools/mac_triage.rs` | allow-listed subprocess: `mac_apt` modules | A/B (macOS triage) |
| `cloud_audit` | `tools/cloud_audit.rs` | in-process flat JSON audit parser | B (cloud/identity audit) |
| `journalctl_query` | `tools/journalctl_query.rs` | fixed subprocess: `journalctl` | A/B (Linux logs) |
| `login_accounting` | `tools/login_accounting.rs` | fixed subprocess: `last`/accounting parser | A/B (Linux login accounting) |
| `ausearch` | `tools/ausearch.rs` | fixed subprocess: `ausearch` | A/B (Linux auditd) |
| `nfdump_query` | `tools/nfdump_query.rs` | fixed subprocess: `nfdump` | B (NetFlow) |
| `suricata_eve` | `tools/suricata_eve.rs` | in-process JSONL parser | B (IDS alerts) |
| `indx_parse` | `tools/indx_parse.rs` | fixed parser wrapper for INDX/I30 data | A (NTFS internals) |
| `vel_collect` | `tools/vel_collect.rs` | subprocess: `velociraptor` (Apache-2.0) | A/B (live response) |
| `sysmon_network_query` | `tools/sysmon_network_query.rs` | in-process: `evtx = 0.11.2` | B (network) |
| `zeek_summary` | `tools/zeek_summary.rs` | in-process TSV parser | B (network) |
| `pcap_triage` | `tools/pcap_triage.rs` | fixed subprocess: `tshark` or `zeek` | B (network) |
| `oe_dbx_parse` | `tools/oe_dbx_parse.rs` | in-process: OE-signature-validated DBX reader (RFC822 headers) | A/B (mail/news store) |

The `vol_pslist` + `vol_psscan` pair is deliberately redundant — pslist walks the kernel's `PsActiveProcessHead` linked list, psscan signature-scans EPROCESS pool memory. Divergence between the two outputs IS the forensic finding (T1014/Rootkit, DKOM unlink). `vol_psxview` is the follow-up cross-view corroborator; do not fold these tools together.

Subprocess tools resolve their binary via a tool-specific env var first (`$HAYABUSA_BIN`, `$VOLATILITY_BIN`, `$VELOCIRAPTOR_BIN`), then PATH lookup. AGPL/GPL backing tools are NEVER linked — see Spec #2 invariant in `CLAUDE.md`.

## Structure for new tools

Every tool module must:

- Export an `Input` struct that `#[derive(serde::Deserialize)]` + `#[serde(deny_unknown_fields)]`.
- Export a typed output that `#[derive(serde::Serialize)]`.
- Export a `<Name>Error` enum with `#[derive(thiserror::Error)]`.
- Expose a pure entrypoint function `pub fn <tool_name>(input: &Input) -> Result<Output, Error>` (or `async fn` when the tool is I/O-bound).
- Never call `std::process::Command` without also declaring the tool invocation in the module docstring (AGPL/GPL binaries run via subprocess only; see `CLAUDE.md`).
- Ship integration tests under `services/mcp/tests/` that use `tempfile` + `FINDEVIL_HOME` override so they never stomp on the developer's real case store.

## Pinned dependencies (Spec #2 §16; see `Cargo.toml` for authoritative pins)

Core MCP plumbing:
- `serde`, `serde_json`, `schemars` (JSON Schema for `tools/list`)
- `thiserror` (structured error types)
- `sha2` (content addressing of evidence + tool outputs)
- `uuid = 1` (`v4` for case IDs)
- `hex` (output digest formatting in `_meta.output_sha256`)
- `chrono` + `serde`
- `tracing`, `tracing-subscriber`
- `tokio` (async runtime; reserved for streaming tools)

Forensic parsers (in-process):
- `evtx = =0.11.2` — Windows Event Log
- `frnsc-prefetch = =0.13.3` + `forensic-rs = =0.13` — Prefetch
- `mft = =0.6.1` — `$MFT` (pinned 0.6.1: 0.7+ requires rustc 1.90)
- `frnsc-hive = =0.13.4` — Registry hives (notatin 1.0.1 broke under rustc 1.88)
- `yara-x = =1.12.0` + `yara-x-{macros,parser,proto} = =1.12.0` — YARA scan (1.13+ requires rustc 1.89)
- `usnjrnl-forensic = =0.6.0` — USN Journal

Subprocess tools (AGPL/GPL, never linked): hayabusa, volatility3, velociraptor.

Development-only: `tempfile`.

> **NB:** `rmcp` is intentionally NOT a runtime dep. The server is a hand-rolled stdio JSON-RPC 2.0 implementation pinned to MCP 2024-11-05 (`src/server.rs`) — chosen for wire-format stability across rmcp churn and to mirror the Python `findevil-agent-mcp` dispatch shape.

## Tests

```sh
# Fast unit tests (single module):
cargo test -p findevil-mcp --lib

# Integration smoke across all tools:
cargo test -p findevil-mcp --test tool_smoke

# Everything:
cargo test --workspace --locked
```

## Notes for contributors

- Do **not** add a dependency without listing it in Spec #2 §16 first.
- Do **not** link AGPL/GPL code (Hayabusa, Chainsaw, Volatility3, Velociraptor, YARA). Subprocess only.
- Every tool's `Input` must `#[serde(deny_unknown_fields)]` to catch schema drift between the Python agent and this crate.
- Every error variant must be safe to surface back to the agent — no filesystem absolute paths that leak private state (case dirs under `FINDEVIL_HOME` are fine; arbitrary agent `cwd` paths are not).
