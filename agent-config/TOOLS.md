# TOOLS.md — MCP Surface

The agent has access to two MCP servers, both auto-spawned by Claude Code via `.mcp.json` at session start. **No `execute_shell` exists** — the typed surface below is the only verb set the agent has.

| Server | Lang | Tools |
|---|---|---|
| `findevil-mcp` | Rust (`services/mcp/`) | 20 typed DFIR tools |
| `findevil-agent-mcp` | Python (`services/agent_mcp/`) | 12 crypto + ACH + memory + ACP + expert-feedback tools (post-A5; the `ots_stamp` + `ots_verify` pair was removed) |

Every successful tool call carries `_meta.output_sha256` (hex SHA-256 of the canonical JSON output). Findings cite tool calls by `tool_call_id`. The verifier vetoes any finding that doesn't.

> **This file is the agent read-order catalog of the 32 typed PRODUCT tools** (the only verbs in
> the audit chain). The *full* set of MCP servers actually registered in `.mcp.json` (incl. the
> operator-runtime `n8n-mcp`, `playwright`, `puppeteer` that emit no Findings) and the external
> DFIR binaries + dependency pins are inventoried in
> [`docs/reference/mcp-and-tools.md`](../docs/reference/mcp-and-tools.md) and
> [`docs/reference/dependencies.md`](../docs/reference/dependencies.md). Tool counts here are
> authoritative — keep them in sync, don't diverge.

---

## Rust DFIR tools (`findevil-mcp`)

### case_open
Args: `{image_path: str, expected_sha256?: str, label?: str}`
Returns: `{id, image_path, image_hash, size_bytes, opened_at}`
Use when: starting an investigation. **Must be called first** — every subsequent tool needs the `case_id`. The image hash is the first audit-chain leaf; if the agent passes `expected_sha256` and it doesn't match, `case_open` errors before any other tool runs.

### evtx_query
Args: `{case_id, evtx_path, eids?: int[], xpath?: str, limit?}`
Returns: `{rows[], row_count, records_seen, parse_errors}`
Use when: account/logon/service/scheduled-task/process-creation questions. In-process via `evtx = 0.11.2` (~1600× faster than python-evtx). `eids` is the cheap EventID filter; `xpath` is accepted for forward compatibility but not applied by the shipped Rust tool today. Always pair Type 3 (Network logon) findings with the source IP — internal RFC1918 is almost always benign.

### prefetch_parse
Args: `{case_id, prefetch_path}`
Returns: `{executable_name, run_count, last_run_times[], volumes[], file_references[], prefetch_hash}`
Use when: confirming execution. Every `.pf` file proves the named binary ran on this host at the named UTC times — not just "was registered." Prefer this over Amcache (which is *catalog*-registration time, not execution).

### mft_timeline
Args: `{case_id, mft_path, since_iso?, until_iso?, limit?}`
Returns: `{rows[], rows_seen, parse_errors}` where each row is `{ts, src_attr ($SI/$FN), path, size, inode, is_allocated}`
Use when: filesystem creation/modification ordering, especially for "what changed in the compromise window?" Prefer `$FN` over `$SI` (anti-forensics tooling stomps `$SI`, rarely `$FN`). Read `is_allocated` to detect deleted files.

### registry_query
Args: `{case_id, hive_path, key_path, value_name?, recursive?, depth?, limit?}`
Returns: `{entries[]}` with `{key, name, type, data}` formatted by RegValue type (REG_SZ→text, REG_MULTI_SZ→pipe-joined, REG_DWORD→decimal, REG_BINARY→hex truncated at 4096B)
Use when: persistence questions (Run/RunOnce, Services, IFEO, AppInit_DLLs), user-context (NTUSER.DAT shellbags, MRUs), ShimCache, BAM. Pass the primary hive only; transaction logs (`.LOG1` / `.LOG2`) are not auto-merged. `recursive=true` walks depth-first capped at 16 by default.

### yara_scan
Args: `{case_id, target_path, rules_path, recursive?, limit?}`
Returns: `{matches[], files_scanned, rules_compiled, scan_errors}`
Use when: IOC matching. In-process via `yara-x = 1.12.0` (BSD-3-Clause, VirusTotal pure-Rust YARA). Each match shows `{rule_name, namespace, tags, pattern_matches[]}` with offset+length+64-byte hex preview. **Always cite the rule name in findings.** Prefer YARA-Forge `core` tier (curated low-FP); `extended`/`community` tiers without corroboration are FP-prone.

### usnjrnl_query
Args: `{case_id, usnjrnl_path, since_iso?, until_iso?, reasons[]?, limit?}`
Returns: `{entries[], records_seen, parse_errors, row_count, major_version}`
Use when: tracking filesystem changes the MFT can't show (deleted-file event sequences, rename chains, hard-link manipulation). `reasons[]` filters by USN reason flag names (FILE_CREATE, FILE_DELETE, RENAME_NEW_NAME, etc.; case-insensitive). Multi-GB journals stream — no OOM.

### hayabusa_scan
Args: `{case_id, evtx_dir, rules_dir?, min_level?, limit?}`
Returns: `{events[], events_seen, stderr_tail}` where each event is `{timestamp_iso, rule, level, channel, event_id, computer, details}`
Use when: Sigma-rule sweep over an EVTX directory. Subprocess to `hayabusa` (AGPL — never linked). `min_level` ∈ {informational, low, medium, high, critical}. Pre-compiled Hayabusa rules expected at `~/hayabusa/rules` unless `rules_dir` is overridden. False-positive note: routine admin activity (Sysinternals tools, scheduled WMI, AV updates) trips medium-severity rules; pair every Hayabusa hit with `prefetch_parse` and `evtx_query 4624` cross-corroboration before believing it.

### sysmon_network_query
Args: `{case_id, evtx_path, event_ids?, since_iso?, until_iso?, image_contains?, destination_ip?, destination_port?, limit?}`
Returns: `{rows[], row_count, records_seen, parse_errors}` where each row normalizes Sysmon network fields (`Image`, `SourceIp`, `DestinationIp`, ports, protocol, user) and preserves raw fields.
Use when: Sysmon Operational logs are available and Pool B needs endpoint-side outbound connection evidence. Event ID 3 is the default. This is EVTX parsing in-process, not a shell wrapper.

### zeek_summary
Args: `{case_id, zeek_path, limit?}`
Returns: `{log_files, rows_seen, conn_count, dns_count, http_count, tls_count, top_hosts[], top_dns_queries[], top_http_hosts[], notable_connections[], parse_errors}`
Use when: Zeek logs are supplied directly or produced from PCAP. Pure parser for Zeek TSV logs; treats rows as network telemetry leads, not exfil proof by itself.

### pcap_triage
Args: `{case_id, pcap_path, analyzer?: "auto"|"tshark"|"zeek", limit?}`
Returns: `{analyzer, packets_seen, conversations[], dns_queries[], http_hosts[], zeek?, stderr_tail}`
Use when: raw PCAP/PCAPNG is supplied. Uses fixed `tshark`/`zeek` subprocess argv only; no raw shell. `auto` prefers tshark, then Zeek. Missing binaries are an environment limitation, not evidence absence.

### vol_pslist
Args: `{case_id, memory_path, pid_filter?: int[], limit?}`
Returns: `{processes[], processes_seen, stderr_tail}` where each process is `{pid, ppid, image_name, create_time_iso, exit_time_iso?, threads, handles, session_id, wow64}`
Use when: enumerating processes from a memory image via the kernel's active list. **Always pair with `vol_psscan` for DKOM cross-validation.** pslist=0 + psscan>0 *can* be the T1014 (Rootkit) signature — but **disambiguate from an acquisition smear / kernel-global read failure before asserting T1014**: if `psscan` recovered core OS singletons (System/csrss/lsass) or duplicate `System` (PID 4) EPROCESS, or `windows.info` shows `KeNumberProcessors`=0, the active-list walk failed for the whole image (smear) rather than a rootkit unlinking a few processes — label it a HYPOTHESIS and require ≥2 artifact classes for T1014. Subprocess to `volatility3` (BSD-2 — never linked, env var `$VOLATILITY_BIN` first then PATH).

### vol_psscan
Args: `{case_id, memory_path, pid_filter?: int[], limit?}`
Returns: `{processes[], processes_seen, stderr_tail}` — same shape as `vol_pslist` but with `offset_v` (EPROCESS virtual address)
Use when: cross-validating `vol_pslist` for DKOM detection. psscan signature-scans EPROCESS pool memory, finding orphaned `_EPROCESS` blocks unlinked from the active list. **The redundancy is deliberate** — divergence between pslist and psscan IS the rootkit finding.

### vol_psxview
Args: `{case_id, memory_path, pid_filter?: int[], limit?}`
Returns: `{processes[], processes_seen, stderr_tail}` where each process is `{pid, image_name, offset_v?, pslist?, psscan?, thrdproc?, pspcid?, csrss?, session?, deskthrd?, exit_time_iso?}`
Use when: corroborating DKOM process hiding after `vol_pslist` and `vol_psscan` diverge. `psxview` cross-references multiple process-enumeration views so the analyst can see which views miss a process and which views still recover it. This is the direct follow-up for the SRL-2018 DC finding.

### vol_malfind
Args: `{case_id, memory_path, pid_filter?: int[], limit?}`
Returns: `{injections[], injections_seen, stderr_tail}` where each injection is `{pid, image_name, vad_start_hex, vad_end_hex, protection, mz_match: bool, sample_hex}` (64-byte preview)
Use when: hunting injected code (T1055). `mz_match=true` + RWX `protection` + non-Microsoft-signed parent process = high-confidence injection. Slowest of the vol_* tools — give it a 30-minute timeout on 5GB+ memory images (the orchestrator already does).

### vel_collect
Args: `{case_id, artifact: str, args?: {str: str}, format?, limit?}`
Returns: `{rows[], rows_seen, stderr_tail}` — `rows` are free-form (every Velociraptor artifact has its own column shape; typed-here would be hostile)
Use when: any of Velociraptor's 200+ DFIR artifacts (`Windows.Forensics.Prefetch`, `Generic.Forensic.LocalHashes`, etc.). `artifact` validated against dotted-path pattern, `args` keys validated against `[A-Za-z_][A-Za-z0-9_]*` to block flag injection. Subprocess to `velociraptor` (Apache-2.0; env var `$VELOCIRAPTOR_BIN` first then PATH).

### browser_history
Args: `{case_id, history_path: str, limit?: int}`
Returns: `{browser_family, rows[]: {url, title, last_visit_time_iso, visit_count}, rows_seen}`
Use when: an extracted browser history DB — Chrome/Edge `History` or Firefox `places.sqlite` — is in scope (downloaded-payload URL, phishing visit, C2 panel). Opened read-only + `immutable=1` (no `-wal`/`-journal` write on evidence); browser auto-detected by schema; timestamps normalized to ISO-8601Z from each native epoch (Chrome WebKit µs-since-1601, Firefox µs-since-1970). HONEST SCOPE: a row CONFIRMS a URL was *recorded as visited* at T — a browser-artifact fact, NOT execution, so a single `browser_history` Finding is a legitimate CONFIRMED browser fact and never trips the ≥2-artifact-class rule; intent is a separate `hypothesis:` layer. In-process via `rusqlite` (MIT, vendored SQLite).

---

## Python crypto + ACH tools (`findevil-agent-mcp`)

### audit_append
Args: `{path, kind, payload}`
Returns: `{seq, ts, kind, prev_hash, line_hash}`
Use when: writing any record to the hash-chained audit log. Every tool call, finding emission, and agent message goes here. The `prev_hash` is auto-computed.

### audit_verify
Args: `{path}`
Returns: `{ok: bool, record_count, error}`
Use when: replaying an audit chain to confirm integrity. Walk every `prev_hash` SHA-256 link; first mismatch reports the seq + field. The `manifest_verify` tool calls this internally.

### manifest_finalize
Args: `{case_id, run_id, started_at, audit_log_path, output_path, signer, extra?}`
Returns: `{leaf_count, merkle_root_hex, signature_payload_sha256}` — the on-disk manifest also has `signature.cert_fingerprint`, `leaves[]`, `finalized_at`
Use when: closing a case. Builds the rs_merkle tree over every audit-log leaf, signs the canonical body — `signer="ed25519"` (default: real local signature, verifies offline), `"sigstore"` (identity + transparency log; customer-release tier), or `"stub"` (explicit dev placeholder) — and writes `run.manifest.json`. Terminal crypto-custody step under Amendment A5 (the OpenTimestamps + Bitcoin anchor that previously followed was removed — see `docs/cryptographic-attestation.md` for the FRE 902(14) trade-off).

### manifest_verify
Args: `{manifest_path, audit_log_path?}`
Returns: `{overall: bool, audit_chain_ok, merkle_root_ok, signature_present, ...}`
Use when: any third party wants offline verification. Replays the audit chain → recomputes the Merkle root from `leaves[]` → checks signature presence. Tampering with `merkle_root_hex` produces a precise diagnostic naming both the declared and rebuilt roots.

### verify_finding
Args: `{finding, tool_call_index, findevil_mcp_command: list[str]}`
Returns: `{action, finding_id, reason, replay_tool_name, replay_expected_sha256, replay_actual_sha256, replay_matched, replay_error}`
Use when: re-running a finding's cited `tool_call_id` to confirm the original output's SHA-256 still matches. The verifier spawns its own short-lived findevil-mcp child process — same binary, same args, same hash, byte-for-byte. Budget 30s/finding per Spec #2 §8.1.

### detect_contradictions
Args: `{case_id, pool_a, pool_b, resolution_required?: bool}`
Returns: `{contradictions[], pool_a_count, pool_b_count}`
Use when: surfacing Pool A vs Pool B disagreements BEFORE judging. Same-`tool_call_id` findings with different `confidence` levels or contradicting `mitre_technique` labels emit. **Surface the contradictions first; the analyst sees them before the judge merges.**

### judge_findings
Args: `{pool_a_findings, pool_b_findings, pool_a_verifier_actions, pool_b_verifier_actions, budget_seconds?}`
Returns: `{merged[], budget_exceeded: bool, budget_detail}`
Use when: credibility-weighted merge after verification. Each pool's score = `base_confidence × pool_credibility`. Pools that produced corroborating CONFIRMED findings build credibility; pools that produced HYPOTHESIS-only get downweighted.

### correlate_findings
Args: `{findings}`
Returns: `{refined[], outcomes[]}` where each outcome is `{finding_id, action: 'kept'|'downgraded'|'rejected', reason}`
Use when: enforcing the SOUL.md ≥2-artifact-class rule. A finding claiming "X executed" must cite ≥2 distinct artifact classes (Prefetch + Amcache+ShimCache, or EDR + memory). Single-source claims auto-downgrade.

### memory_remember
Args: `{store_path, case_id, kind, key, value, sha256, ts?, case_path?, audit_log_path?}`
Returns: `{case_id, kind, key, sha256}`
Use when: a Finding has been marked `CONFIRMED` by the judge and the IOC / hash / TTP / hostname / one-line summary is worth surfacing in future investigations on different cases. Hermes-pattern (A3 §2.2). The `store_path` is the session-constant `MEMORY_STORE_PATH` resolved by the supervisor at session start; `kind` ∈ `{ioc, hash, ttp, hostname, finding_summary}`; `sha256` is `sha256:` + 64 lowercase hex. Skip for HYPOTHESIS-tier — the memory chain only remembers things the army would stand behind. When `audit_log_path` is set, a `memory_remember` record is appended to the case audit JSONL as process provenance — hash-chained but **never a Merkle leaf and never a `tool_call_id`** (memory is never evidence).

### memory_recall
Args: `{store_path, query, kind?, limit?, audit_log_path?}`
Returns: `{hits: [{case_id, kind, key, value, sha256, ts, confidence}, …]}`
Use when: BEFORE drafting a Finding, to check whether you've seen this IOC / hash / TTP / hostname in a previous investigation. Hits become a `prior_observations` field on the Finding for prioritization and context only; a prior-case hit is not current-case evidence and must not satisfy the SOUL.md >=2 artifact-class rule. When `audit_log_path` is set, a `memory_recall` record is appended as process provenance — hash-chained but **never a Merkle leaf and never a `tool_call_id`**. Hits are returned ordered by BM25 relevance × 90-day decay, descending confidence. **Query semantics: exact phrase match** — the query is phrase-quoted before hitting FTS5, so `evil.com` and `T1059.001` are safe; multi-word queries (`powershell encoded`) become exact-phrase searches and may return zero hits even when both tokens exist separately. Pass single tokens for broad recall.

### pool_handoff
Args: `{audit_path, from_role, to_role, payload, correlation_id?}`
Returns: `{acp_version, from_role, to_role, correlation_id, ts}`
Use when: one role/pool needs to formally hand structured findings or context to another, distinct from natural-language supervisor messaging. Records a `kind="acp_handoff"` line in the case audit JSONL with the IBM-ACP envelope shape (Linux Foundation spec, A3 §2.3). Canonical use sites: **verifier → judge** (always, for each verdict); **Pool A → Pool B** (when handing exfil-staging context that Pool A surfaced while looking for persistence); **supervisor → any role** (when assigning a structured sub-task that includes payload data the receiver needs to act on). The `correlation_id` lets downstream roles thread replies — pass it on the handoff that originates a thread, then pass the same id on subsequent handoffs about the same finding.

### expert_miss_capture
Args: `{case_id, finding_id?, edit_type, edit_text, expert_name?, ledger_path}`
Returns: `{seq, ts, line_hash, prev_hash, github_issue_url?}`
Use when: a human expert edits the auto-drafted PDF before release. Records a `kind="expert_miss"` line in the hash-chained `expert_misses.jsonl` ledger so corrections become connector, playbook, rule, QA, escalation, or language follow-up work. GitHub issue creation is default-off and only attempted when `FINDEVIL_MISS_GH_ENABLED=1`; `FINDEVIL_MISS_GH_REDACT=1` redacts case IDs in issue text.

---

## Invariants

- **Every call emits a `tool_call_id`.** Findings cite it. Verifier vetoes uncited.
- **No tool mutates evidence.** All reads operate on read-only mounts; original images stay untouched.
- **No `execute_shell`.** The narrow typed surface above is the entire verb set. Adding shell pass-through breaks the architectural-guardrail story.
- **AGPL/GPL backing tools (Hayabusa, Volatility3, Velociraptor, YARA core) are subprocess-only — never linked.** Apache-2.0 license clean.
- **All timestamps UTC, ISO-8601, trailing `Z`.** SHA-256 preferred over MD5.
